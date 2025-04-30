create table base_database.atepoztli__authentication_service__schema.resource__resources
(
    id                  bigserial         not null,
    kind                varchar(100)      not null,
    access_key          varchar(255)      not null,
    hashed_secret       bytea             not null,
    salt                bytea             not null,
    specific_attributes json default '{}' not null
);

