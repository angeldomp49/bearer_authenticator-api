create table base_database.atepoztli__authentication_service__schema.black_list__allowed_clients
(
    id  bigserial,
    ip  char(25),
    tag integer default '' not null
);

