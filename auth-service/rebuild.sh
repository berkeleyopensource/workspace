docker build --tag workspace-auth .
docker tag workspace-auth workspaceauth.azurecr.io/workspace-auth
docker push workspaceauth.azurecr.io/workspace-auth