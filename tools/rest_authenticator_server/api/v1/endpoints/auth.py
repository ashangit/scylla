from fastapi import APIRouter, HTTPException

from schema.auth import PostAuth, ResponseAuth

router = APIRouter()


@router.post('/{user}/groups', response_model=ResponseAuth)
async def get_user_groups(user, post: PostAuth) -> ResponseAuth:
    if user == 'scylla_user':
        if post.password == 'not_cassandra':
            return ResponseAuth(username=user, groups=['group1', 'group2'])
        else:
            raise HTTPException(status_code=401, detail=f'Bad password for {user} user')
    else:
        raise HTTPException(status_code=404, detail=f'User {user} not found')
