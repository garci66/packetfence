package pf::dal::roles::has_tenant_id;

=head1 NAME

pf::dal::roles::has_tenant_id -

=cut

=head1 DESCRIPTION

pf::dal::roles::has_tenant_id

=cut

use strict;
use warnings;
use Role::Tiny;

=head2 update_params_for_select

Automatically add the current tenant_id to the where clause of the select statement

=cut

around update_params_for_select => sub {
    my ($orig, $self, %args) = @_;
    return $self->$orig(update_where($self, %args));
};

=head2 update_params_for_update

Automatically add the current tenant_id to the where clause of the update statement

=cut

around update_params_for_update => sub {
    my ($orig, $self, %args) = @_;
    return $self->$orig(update_where($self, %args));
};

=head2 update_where

update_where

=cut

sub update_where {
    my ($self, %args) = @_;
    my $no_auto_tenant_id = delete $args{'-no_auto_tenant_id'};
    unless ($no_auto_tenant_id) {
        my $name = $self->table . ".tenant_id";
        my $where = {
            $name => $self->get_tenant,
        };
        my $old_where = delete $args{-where};
        if (defined $old_where) {
            my $sqla = $self->get_sql_abstract();
            $where =  $sqla->merge_conditions($where, $old_where);
        }
        $args{-where} = $where;
    }
    return %args;
}

=head2 update_params_for_delete

Automatically add the current tenant_id to the where clause of the delete statement

=cut

around update_params_for_delete => sub {
    my ($orig, $self, %args) = @_;
    return $self->$orig(update_where($self, %args));
};

=head2 update_params_for_insert

Automatically add the current tenant_id to the set clause of the insert statement

=cut

around update_params_for_insert => sub {
    my ($orig, $self, %args) = @_;
    unless ($args{'-no_auto_tenant_id'}) {
        my $old_set = delete $args{'-values'} // {};
        $old_set->{tenant_id} = $self->get_tenant;
        $args{'-values'} = $old_set;
    }
    return $self->$orig(%args);
};

=head2 update_params_for_upsert

Automatically add the current tenant_id to the set clause of the upsert statement

=cut

around update_params_for_upsert => sub {
    my ($orig, $self, %args) = @_;
    unless ($args{'-no_auto_tenant_id'}) {
        my $tenant_id = $self->get_tenant;
        my $old_set = delete $args{'-values'} // {};
        $old_set->{tenant_id} = $tenant_id;
        $args{'-values'} = $old_set;
        my $old_conflict = delete $args{-on_conflict} // {};
        $old_conflict->{tenant_id} = $tenant_id;
        $args{'-on_conflict'} = $old_conflict;
    }
    return $self->$orig(%args);
};

=head2 new

=cut

around new => sub {
    my ($orig, $proto, $args) = @_;
    $args //= {};
    unless ($args->{'-no_auto_tenant_id'}) {
        $args->{tenant_id} = $proto->get_tenant;
    }
    return $proto->$orig($args);
};

=head2 build_primary_keys_where_clause

=cut

around build_primary_keys_where_clause => sub {
    my ($orig, $self, $ids) = @_;
    return $self->$orig({%$ids, tenant_id => $self->get_tenant});
};

=head2 around _defaults

Add tenant_id to the defaults

=cut

around _defaults => sub {
    my ($orig, $self) = @_;
    my $defaults = $self->$orig();
    $defaults->{tenant_id} = $self->get_tenant;
    return $defaults;
};
 
=head1 AUTHOR

Inverse inc. <info@inverse.ca>

=head1 COPYRIGHT

Copyright (C) 2005-2018 Inverse inc.

=head1 LICENSE

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
USA.

=cut

1;
