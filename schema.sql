drop table if exists user;
create table user (
  user_id integer primary key autoincrement,
  username text not null,
  password_hash text not null
);

drop table if exists passwords;
create table passwords (
  password_id integer primary key autoincrement,
  site text not null,
  password text not null,
  user_id integer not null
);
