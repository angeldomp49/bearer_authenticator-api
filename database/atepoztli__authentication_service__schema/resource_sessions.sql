create table base_database.atepoztli__authentication_service__schema.resource_sessions
(
    id              bigserial,
    resource_id     bigint                not null,
    expiration_date date    default now() not null,
    is_closed       boolean default true  not null,
    permissions     json    default '{
      "permissions": []
    }'                                    not null
);

