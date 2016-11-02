package pf::web::externalportal;

=head1 NAME

pf::web::externalportal - handle the detection of an external portal workflow

=cut

=head1 DESCRIPTION

pf::web::externalportal detect external portal workflow

=cut

use strict;
use warnings;

use Apache2::Const -compile => qw(:http);
use Apache2::Request;
use Apache2::RequestRec;
use Apache2::Connection;
use Hash::Merge qw(merge);
use UNIVERSAL::require;

use pf::config qw(
    $WIRELESS_MAC_AUTH
);
use pf::iplog;
use pf::log;
use pf::locationlog qw(locationlog_view_open_mac locationlog_get_session);
use pf::Portal::Session;
use pf::util;
use pf::web::constants;
use pf::web::util;
use pf::constants;

=head1 SUBROUTINES

=over

=item new

=cut

sub new {
   my $logger = get_logger();
   $logger->debug("instantiating new pf::web::externalportal");
   my ( $class, %argv ) = @_;
   my $self = bless {}, $class;
   return $self;
}


=item handle

handle the detection of the external portal

=cut

sub handle {
    my ( $self, $r ) = @_;
    my $logger = get_logger;

    my $req = Apache2::Request->new($r);
    my $uri = $r->uri;

    # Discarding non external portal requests
    unless ( $uri =~ /$WEB::EXTERNAL_PORTAL_URL/o ) {
        $logger->debug("Tested URI '$uri' against external portal mechanism and does not appear to be one.");
        return $FALSE;
    }

    # Parsing external portal URL information for switch handling
    # URI will usually be in the form (/Switch::Type/sid424242), where:
    # - Switch::Type will be the switch type to instantiate (mandatory)
    # - sid424242 is the optional PacketFence session ID to track the session when working by session ID and not by URI parameters
    $logger->info("URI '$uri' is detected as an external captive portal URI");
    $uri =~ /\/([^\/]*)/;
    my $switch_type = $1;
    $switch_type = "pf::Switch::$switch_type";
    if ( !(eval "$switch_type->require()") ) {
        $logger->error("Cannot load perl module for switch type '$switch_type'. Either switch type is unknown or switch type perl module have compilation errors. " .
        "See the following message for details: $@");
        return $FALSE;
    }
    # Making sure switch supports external portal
    return $FALSE unless $switch_type->supportsExternalPortal;

    my %params = (
        session_id      => undef,   # External portal session ID when working by session ID flow
        switch_id       => undef,   # Switch ID
        client_mac      => undef,   # Client (endpoint) MAC address
        client_ip       => undef,   # Client (endpoint) IP address
        ssid            => undef,   # SSID connecting to
        redirect_url    => undef,   # Redirect URL
        grant_url       => undef,   # Grant URL
        status_code     => undef,   # Status code
    );

    my $switch_params = $switch_type->parseExternalPortalRequest($r, $req);
    unless ( defined($switch_params) ) {
        $logger->error("Error in parsing external portal request from switch module");
        return $FALSE;
    }
    %params = %{ merge(\%params, $switch_params) };
    
    $logger->debug(sub { use Data::Dumper; "Handling external portal request using the following parameters: " . Dumper(%params) });

    unless ( defined($params{'switch_id'}) ) {
        $logger->error("Trying to handle external portal request without a valid switch ID.");
        return $FALSE;
    }

    unless ( (defined($params{'client_mac'})) && (defined($params{'client_ip'})) ) {
        $logger->error("Trying to handle external portal request without a valid client mac / ip.");
        return $FALSE;
    }

    my $switch = pf::SwitchFactory->instantiate($params{'switch_id'});

    unless ( ref($switch) ) {
        $logger->error("Unable to instantiate switch object using switch_id '" . $params{'switch_id'} . "'");
        return $FALSE;
    }

    pf::iplog::open($params{'client_ip'}, $params{'client_mac'}, 3600);

    # Updating locationlog unless there is a session ID parameter, which means a locationlog entry was already opened on session creation
    $switch->synchronize_locationlog("0", "0", $params{'client_mac'}, 0, $WIRELESS_MAC_AUTH, $params{'client_mac'}, $params{'ssid'}) unless ( defined($params{'session_id'}) );

    my $portalSession = $self->_setup_session($req, $params{'client_mac'}, $params{'client_ip'}, $params{'redirect_url'}, $params{'grant_url'});

    return ( $portalSession->session->id(), $params{'redirect_url'} );
}


sub _setup_session {
    my ( $self, $req, $client_mac, $client_ip, $redirect_url, $grant_url ) = @_;
    my $logger = get_logger();
    $logger->trace(sub { use Data::Dumper ; "_setup_session params :".Dumper(\@_) });
    my %info = (
        'client_mac' => $client_mac,
    );
    my $portalSession = pf::Portal::Session->new(%info);
    $portalSession->setClientIp($client_ip) if (defined($client_ip));
    $portalSession->setDestinationUrl($redirect_url) if (defined($redirect_url));
    $portalSession->setGrantUrl($grant_url) if (defined($grant_url));
    $portalSession->session->param('is_external_portal', $TRUE);
    if(defined($req)){
        my $params = $req->param // {};
        foreach my $key (keys %$params) {
            $logger->debug("Adding additionnal session parameter for url detected : $key : ".$req->param($key));
            $portalSession->session->param("ecwp-original-param-$key", $req->param($key));
        }
    }
    return $portalSession;

}


=back

=head1 AUTHOR

Inverse inc. <info@inverse.ca>

=head1 COPYRIGHT

Copyright (C) 2005-2016 Inverse inc.

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
