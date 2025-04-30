create table base_database.atepoztli__authentication_service__schema.resource__secret_keys
(
    id          bigserial,
    secret_key  varchar(255) not null,
    resource_id bigint       not null
);

