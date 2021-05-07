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

#pragma once

#include <seastar/core/abort_source.hh>

#include "auth/authenticator.hh"
#include "auth/rest_http_client.hh"
#include "cql3/query_processor.hh"

namespace service {
    class migration_manager;
}

namespace auth {

    extern const std::string_view rest_authenticator_name;

    class rest_authenticator : public authenticator {
        cql3::query_processor &_qp;
        ::service::migration_manager &_migration_manager;
        authenticator_config _authenticator_config;
        future<> _stopped;
        seastar::abort_source _as;
        rest_http_client _rest_http_client;

    public:
        static db::consistency_level consistency_for_user(std::string_view role_name);

        rest_authenticator(cql3::query_processor &, ::service::migration_manager &);

        virtual future<> start() override;

        virtual future<> stop() override;

        virtual std::string_view qualified_java_name() const override;

        virtual bool require_authentication() const override;

        virtual authentication_option_set supported_options() const override;

        virtual authentication_option_set alterable_options() const override;

        virtual future <authenticated_user> authenticate(const credentials_map &credentials) const override;

        virtual future<> create(std::string_view role_name, const authentication_options &options) const override;

        virtual future<> alter(std::string_view role_name, const authentication_options &options) const override;

        virtual future<> drop(std::string_view role_name) const override;

        virtual future <custom_options> query_custom_options(std::string_view role_name) const override;

        virtual const resource_set &protected_resources() const override;

        virtual ::shared_ptr <sasl_challenge> new_sasl_challenge() const override;

        virtual void set_authenticator_config(authenticator_config &authenticator_config) override;

    private:
        bool legacy_metadata_exists() const;

        future<> migrate_legacy_metadata() const;

        future<> create_default_if_missing() const;

        future <authenticated_user>
        create_or_update(bool user_to_create, std::string_view username, std::string_view password,
                         std::vector <std::string> groups) const;

        future<> create_with_groups(std::string_view role_name, std::vector <std::string> groups,
                                    const authentication_options &options) const;

    };

}

