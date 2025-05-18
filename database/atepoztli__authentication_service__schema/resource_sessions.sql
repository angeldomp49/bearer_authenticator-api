create table base_database.atepoztli__authentication_service__schema.resource__sessions
(
    id              bigserial,
    resource_id     bigint                not null,
    expiration_date bigint    default extract(epoch from now())::bigint not null,
    is_closed       boolean default true  not null,
    permissions     json    default '{
      "permissions": []
    }'                                    not null
);

