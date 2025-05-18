create table base_database.atepoztli__authentication_service__schema.black_list__forbbiden_clients
(
    id  bigserial               not null,
    ip  char(30),
    tag varchar(255) default '' not null,
    constraint black_list__forbbiden_clients_pk
        primary key (id)
);

