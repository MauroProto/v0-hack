create table public.accounts (
  id uuid primary key,
  email text not null
);

alter table public.accounts disable row level security;

create function public.admin_delete_account(account_id uuid)
returns void
language plpgsql
security definer
as $$
begin
  delete from public.accounts where id = account_id;
end;
$$;
