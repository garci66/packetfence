package pfappserver::PacketFence::Controller::DynamicReport;

=head1 NAME

pfappserver::PacketFence::Controller::DynamicReport - Catalyst Controller

=head1 DESCRIPTION

Controller for dynamic reports

=cut

use HTTP::Status qw(:constants is_error is_success);
use Moose;  # automatically turns on strict and warnings
use namespace::autoclean;

use pf::factory::report;

BEGIN {
    extends 'pfappserver::Base::Controller';
}

__PACKAGE__->config(
    action_args => {
        'search' => { form => 'DynamicReportSearch' },
    }
);

sub index :Path :Args(1) :AdminRole('REPORTS_READ') {
    my ($self, $c, $report_id) = @_;

    $c->stash->{template} = "dynamicreport/index.tt";
    $c->forward("_search", [$report_id]);
}

sub search :Local :AdminRole('REPORTS_READ') {
    my ($self, $c) = @_;

    my $report_id = $c->req->param('report_id');

    my $form = $self->getForm($c);
    $form->process(params => $c->request->params);

    my $search = $form->value;

    $c->stash->{template} = "dynamicreport/search.tt";
    $c->forward("_search", [$report_id, $search]);
}

sub _search :AdminRole('REPORTS_READ') {
    my ($self, $c, $report_id, $form) = @_;
    my $report = $c->stash->{report} = pf::factory::report->new($report_id);

    $form //= {};
    $c->stash->{page_num} = $c->request->param("page_num") // 1;
    my %infos = (
        page => $c->stash->{page_num}, 
        per_page => $form->{"per_page"},
        search => {
            type => $form->{"all_or_any"},
        },
    );

    if($form->{searches}) {
        foreach my $search (@{$form->{searches}}) {
            $infos{search}{conditions} //= [];
            push @{$infos{search}{conditions}}, {field => $search->{name}, operator => $search->{op}, value => $search->{value}}
        }
    }

    $infos{start_date} = $form->{start}->{date} . " " . $form->{start}->{time} if($form->{start});
    $infos{end_date} = $form->{end}->{date} . " " . $form->{end}->{time} if($form->{end});

    my ($status, $items) = $report->query(%infos);

    $c->stash->{searches} = $report->searches;
    $c->stash->{items} = $items;
    $c->stash->{page_count} = $report->page_count(%infos);

    if ($c->request->param('export')) {
        $c->stash({
            current_view => 'CSV',
        });
    }
}

=head1 COPYRIGHT

Copyright (C) 2016-2021 Inverse inc.

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

__PACKAGE__->meta->make_immutable unless $ENV{"PF_SKIP_MAKE_IMMUTABLE"};

1;
