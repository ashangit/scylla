/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Copyright (C) 2016 ScyllaDB
 *
 * Modified by ScyllaDB
 */

/*
 * This file is part of Scylla.
 *
 * Scylla is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Scylla is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Scylla.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "auth/rest_authenticator.hh"

#include <algorithm>
#include <chrono>
#include <random>
#include <string_view>
#include <optional>

#include <boost/algorithm/cxx11/all_of.hpp>
#include <seastar/core/seastar.hh>

#include "auth/authenticated_user.hh"
#include "auth/common.hh"
#include "auth/passwords.hh"
#include "auth/roles-metadata.hh"
#include "cql3/untyped_result_set.hh"
#include "log.hh"
#include "service/migration_manager.hh"
#include "utils/class_registrator.hh"
#include "database.hh"

// TODO what about picojson.hh
namespace auth {

    constexpr std::string_view
    rest_authenticator_name("com.criteo.scylladb.auth.RestAuthenticator");

// name of the hash column.
    static constexpr std::string_view
    SALTED_HASH = "salted_hash";
    static constexpr std::string_view
    DEFAULT_USER_NAME = meta::DEFAULT_SUPERUSER_NAME;
    static const sstring DEFAULT_USER_PASSWORD = sstring(meta::DEFAULT_SUPERUSER_NAME);

    static logging::logger plogger("rest_authenticator");

// To ensure correct initialization order, we unfortunately need to use a string literal.
    static const class_registrator<
            authenticator,
            rest_authenticator,
            cql3::query_processor &,
            ::service::migration_manager &,
            authenticator_config> rest_auth_reg("com.criteo.scylladb.auth.RestAuthenticator");

    static thread_local auto rng_for_salt = std::default_random_engine(std::random_device{}());

    rest_authenticator::rest_authenticator(cql3::query_processor &qp, ::service::migration_manager &mm,
                                           authenticator_config ac)
            : _qp(qp), _migration_manager(mm), _authenticator_config(std::move(ac)), _stopped(make_ready_future<>()) {}

    static bool has_salted_hash(const cql3::untyped_result_set_row &row) {
        return !row.get_or<sstring>(SALTED_HASH, "").empty();
    }

    static const sstring &update_row_query() {
        static const sstring update_row_query = format("UPDATE {} SET {} = ? WHERE {} = ?",
                                                       meta::roles_table::qualified_name,
                                                       SALTED_HASH,
                                                       meta::roles_table::role_col_name);
        return update_row_query;
    }

    static const sstring &create_row_query(uint32_t ttl) {
        static const sstring create_row_query = format(
                "INSERT INTO {} ({}, can_login, is_superuser, member_of, {}) VALUES (?, true, false, {{}}, ?) USING TTL {}",
                meta::roles_table::qualified_name,
                meta::roles_table::role_col_name,
                SALTED_HASH,
                ttl);

        return create_row_query;
    }

    static const sstring legacy_table_name{"credentials"};

    future<> rest_authenticator::create_default_if_missing() const {
        return default_role_row_satisfies(_qp, &has_salted_hash).then([this](bool exists) {
            if (!exists) {
                return _qp.execute_internal(
                        update_row_query(),
                        db::consistency_level::QUORUM,
                        internal_distributed_timeout_config(),
                        {passwords::hash(DEFAULT_USER_PASSWORD, rng_for_salt), DEFAULT_USER_NAME}).then([](auto &&) {
                    plogger.info("Created default superuser authentication record.");
                });
            }

            return make_ready_future<>();
        });
    }

    future<> rest_authenticator::start() {
        // Init rest http client
        _rest_http_client = rest_http_client(_authenticator_config.rest_authenticator_endpoint_host,
                                             _authenticator_config.rest_authenticator_endpoint_port,
                                             _authenticator_config.rest_authenticator_endpoint_cafile_path);

        return once_among_shards([this] {
            auto f = create_metadata_table_if_missing(
                    meta::roles_table::name,
                    _qp,
                    meta::roles_table::creation_query(),
                    _migration_manager);

            _stopped = do_after_system_ready(_as, [this] {
                return async([this] {
                    wait_for_schema_agreement(_migration_manager, _qp.db(), _as).get0();

                    if (any_nondefault_role_row_satisfies(_qp, &has_salted_hash).get0()) {
                        return;
                    }

                    create_default_if_missing().get0();
                });
            });

            return f;
        }).then([this]() {
            return _rest_http_client.init();
        });
    }

    future<> rest_authenticator::stop() {
        _as.request_abort();
        return _stopped.handle_exception_type([](const sleep_aborted &) {}).handle_exception_type(
                [](const abort_requested_exception &) {});
    }

    db::consistency_level rest_authenticator::consistency_for_user(std::string_view role_name) {
        if (role_name == DEFAULT_USER_NAME) {
            return db::consistency_level::QUORUM;
        }
        return db::consistency_level::LOCAL_ONE;
    }

    std::string_view rest_authenticator::qualified_java_name() const {
        return rest_authenticator_name;
    }

    bool rest_authenticator::require_authentication() const {
        return true;
    }

    authentication_option_set rest_authenticator::supported_options() const {
        return authentication_option_set{authentication_option::password};
    }

    authentication_option_set rest_authenticator::alterable_options() const {
        return authentication_option_set{authentication_option::password};
    }

    future <authenticated_user> rest_authenticator::authenticate(
            const credentials_map &credentials) const {
        if (!credentials.contains(USERNAME_KEY)) {
            plogger.info("Required key 'USERNAME' is missing");
            throw exceptions::authentication_exception(format("Required key '{}' is missing", USERNAME_KEY));
        }
        if (!credentials.contains(PASSWORD_KEY)) {
            plogger.info("Required key 'PASSWORD' is missing");
            throw exceptions::authentication_exception(format("Required key '{}' is missing", PASSWORD_KEY));
        }

        auto &username = credentials.at(USERNAME_KEY);
        auto &password = credentials.at(PASSWORD_KEY);

        // Here was a thread local, explicit cache of prepared statement. In normal execution this is
        // fine, but since we in testing set up and tear down system over and over, we'd start using
        // obsolete prepared statements pretty quickly.
        // Rely on query processing caching statements instead, and lets assume
        // that a map lookup string->statement is not gonna kill us much.
        return futurize_invoke([this, username, password] {
            static const sstring query = format("SELECT {} FROM {} WHERE {} = ?",
                                                SALTED_HASH,
                                                meta::roles_table::qualified_name,
                                                meta::roles_table::role_col_name);

            return _qp.execute_internal(
                    query,
                    consistency_for_user(username),
                    internal_distributed_timeout_config(),
                    {username},
                    true);
        }).then_wrapped([=](future<::shared_ptr < cql3::untyped_result_set>>
        f) {
            try {
                auto res = f.get0();
                auto salted_hash = std::optional<sstring>();
                if (!res->empty()) {
                    salted_hash = res->one().get_opt<sstring>(SALTED_HASH);
                }

                if (!salted_hash || !passwords::check(password, *salted_hash)) {
                    bool user_to_create = res->empty();

                    // TODO manage retry?
                    // TODO add prometheus metrics on auth failure/success...?
                    // TODO better delete only if date passed and repopulate async instead of ttl that just remove the entry from the table
                    plogger.info("Authenticating username {} from rest endpoint", username);
                    // This timeout only timebox return to client the task and callback are not cancelled
                    return with_timeout(
                            timer<>::clock::now() +
                            std::chrono::seconds(_authenticator_config.rest_authenticator_endpoint_timeout),
                            _rest_http_client.connect()
                                    .then([this, user_to_create, username, password](std::unique_ptr <rest_http_client::connection> c) {
                                        return c->do_get_groups(username, password)
                                                .then([this, c=std::move(c), user_to_create, username, password](
                                                        std::vector <std::string> groups) {
                                                    return create_or_update(user_to_create, username, password, groups);
                                                });
                                                //.finally([c] {
                                                //    delete c;
                                                //});
                                    }));
                }

                return make_ready_future<authenticated_user>(username);
            } catch (std::system_error &) {
                std::throw_with_nested(exceptions::authentication_exception("Could not verify password"));
            } catch (exceptions::request_execution_exception &e) {
                std::throw_with_nested(exceptions::authentication_exception(e.what()));
            } catch (exceptions::authentication_exception &e) {
                std::throw_with_nested(e);
            } catch (...) {
                std::throw_with_nested(exceptions::authentication_exception("authentication failed"));
            }
        });
    }

    future <authenticated_user>
    rest_authenticator::create_or_update(bool user_to_create, std::string_view username, std::string_view password,
                                         std::vector <std::string> groups) const {
        authentication_options authen_options;
        authen_options.password = std::optional < std::string > {password};

        if (user_to_create) {
            plogger.info("Create role for username {}", username);
            return rest_authenticator::create_with_groups(username, groups, authen_options).then([username] {

                return make_ready_future<authenticated_user>(username);
            });
        }
        plogger.info("Update password for username {}", username);
        return rest_authenticator::alter(username, authen_options).then([username] {
            return make_ready_future<authenticated_user>(username);
        });
    }

    future<> rest_authenticator::create(std::string_view role_name, const authentication_options &options) const {
        std::vector <std::string> groups;
        return create_with_groups(role_name, groups, options);
    }

    future<> rest_authenticator::create_with_groups(std::string_view role_name, std::vector <std::string> groups,
                                                    const authentication_options &options) const {
        if (!options.password) {
            return make_ready_future<>();
        }

        return _qp.execute_internal(
                create_row_query(_authenticator_config.rest_authenticator_endpoint_ttl),
                consistency_for_user(role_name),
                internal_distributed_timeout_config(),
                {sstring(role_name), passwords::hash(*options.password, rng_for_salt)}).discard_result();
    }

    future<> rest_authenticator::alter(std::string_view role_name, const authentication_options &options) const {
        if (!options.password) {
            return make_ready_future<>();
        }

        static const sstring query = format("UPDATE {} SET {} = ? WHERE {} = ?",
                                            meta::roles_table::qualified_name,
                                            SALTED_HASH,
                                            meta::roles_table::role_col_name);

        return _qp.execute_internal(
                query,
                consistency_for_user(role_name),
                internal_distributed_timeout_config(),
                {passwords::hash(*options.password, rng_for_salt), sstring(role_name)}).discard_result();
    }

    future<> rest_authenticator::drop(std::string_view name) const {
        static const sstring query = format("DELETE {} FROM {} WHERE {} = ?",
                                            SALTED_HASH,
                                            meta::roles_table::qualified_name,
                                            meta::roles_table::role_col_name);

        return _qp.execute_internal(
                query, consistency_for_user(name),
                internal_distributed_timeout_config(),
                {sstring(name)}).discard_result();
    }

    future <custom_options> rest_authenticator::query_custom_options(std::string_view role_name) const {
        return make_ready_future<custom_options>();
    }

    const resource_set &rest_authenticator::protected_resources() const {
        static const resource_set resources({make_data_resource(meta::AUTH_KS, meta::roles_table::name)});
        return resources;
    }

    ::shared_ptr <sasl_challenge> rest_authenticator::new_sasl_challenge() const {
        return ::make_shared<plain_sasl_challenge>([this](std::string_view username, std::string_view password) {
            credentials_map credentials{};
            credentials[USERNAME_KEY] = sstring(username);
            credentials[PASSWORD_KEY] = sstring(password);
            return this->authenticate(credentials);
        });
    }

}
