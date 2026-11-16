# Contributing

1. Sqlx offline build

Requires `.sqlx` directory to be present in the root directory of the project. Create the file using:

```
cargo sqlx prepare --workspace -- --all-targets --tests
```

1. Build docker image

```
docker-compose build
```

3. Run

```
docker-compose up
```

## Configuration

Following environment variables can be set to configure orion core service:

* **XGUARD_ADMIN_GROUPNAME**: groupname that give a user privileged access
* **XGUARD_DEFAULT_ADMIN_PASSWORD**: initial password of the default `admin` user

### Authorization

* **XGUARD_JWT_SECRET**: Json Web Token secret, used to encode/decode JWT tokens

### LDAP

* **XGUARD_LDAP_URL**: URL to read users and devices data (e.g. `http://localhost:389`)
* **XGUARD_LDAP_GROUP_SEARCH_BASE**: group search base, default: `ou=groups,dc=example,dc=org`
* **XGUARD_LDAP_USER_SEARCH_BASE**: user search base, default: `dc=example,dc=org`
* **XGUARD_LDAP_USER_OBJ_CLASS**: user object class, default: `inetOrgPerson`
* **XGUARD_LDAP_GROUP_OBJ_CLASS**: group object class, default: `groupOfUniqueNames`
* **XGUARD_LDAP_USERNAME_ATTR**: naming attribute for users, should be `cn` or `uid`, default: `cn`
* **XGUARD_LDAP_GROUPNAME_ATTR**: naming attribute for groups, default: `cn`
* **XGUARD_LDAP_MEMBER_ATTR**: user attribute for group membership
* **XGUARD_LDAP_GROUP_MEMBER_ATTR**: group attibute for memebers

### gRPC

* **XGUARD_GRPC_PORT**: gRPC services bind port, default = `50055`

### HTTP server

* **XGUARD_WEB_PORT**: web services bind port, default = `8000`


### User agents YAML update

```
curl -Lf https://raw.githubusercontent.com/ua-parser/uap-core/master/regexes.yaml | yq -y '.' > crates/xguard_core/user_agent_header_regexes.yaml
```
