create table atepoztli__authentication_service__schema.resource__sessions
(
    id              bigserial,
    resource_id     bigint               not null,
    expiration_date bigint  default 1    not null,
    is_closed       boolean default true not null,
    permissions     json    default '{
      "permissions": []
    }'                                   not null
);

