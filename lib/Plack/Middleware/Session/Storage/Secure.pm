package Plack::Middleware::Session::Storage::Secure;
use 5.10.1;
use strict;
use warnings;
 
our $VERSION   = '0.01';

use Cookie::Baker;
use Plack::Util;
use Session::Storage::Secure 0.010 ();
 
use parent 'Plack::Middleware';

use Plack::Util::Accessor qw/
    session_key
    secret_key
    default_duration
    _sss
    path
    domain
    expires
    secure
    httponly
/;

sub prepare_app {
    my ($self, %opts) = shift;

    $self->session_key( $opts{session_key} // 'plack_session' );

    my $args = {
        secret_key             => $self->secret_key,
        sereal_encoder_options => {snappy => 1, stringify_unknown => 1, croak_on_bless => 1},
        sereal_decoder_options => {validate_utf8 => 1, refuse_objects => 1},
        (( default_duration => $self->default_duration )x!! $self->default_duration),
    };
    $self->_sss( Session::Storage::Secure->new(%$args) );
}
 
sub call {
    my $self = shift;
    my $env  = shift;
 
    $env->{'psgix.session'} = $self->get_session($env);

    my $res = $self->app->($env);

    $self->response_cb($res, sub { $self->finalize($env, $_[0]) });
}
 
sub get_session {
    my($self, $env) = @_;
    
    my $raw = crush_cookie($env->{HTTP_COOKIE})->{$self->session_key};
    return +{} if ! defined $raw;
    
    my $data = $self->_sss->decode($raw);
    return $data // +{};
}

sub finalize {
    my($self, $env, $res) = @_;

    my $session = $env->{'psgix.session'};
    my $options = $env->{'psgix.session.options'};

    $options->{path}     = $self->path || '/' if !exists $options->{path};
    $options->{domain}   = $self->domain      if !exists $options->{domain} && defined $self->domain;
    $options->{secure}   = $self->secure      if !exists $options->{secure} && defined $self->secure;
    $options->{httponly} = $self->httponly    if !exists $options->{httponly} && defined $self->httponly;

    # delete session
    if ( $options->{expire} ) {
        $options->{expires} = time - 1;
    }
 
    if (!exists $options->{expires} && defined $self->expires) {
        $options->{expires} = time + $self->expires;
    }

    $self->_set_cookie($session, $res, $options);
}

sub _set_cookie {
    my($self, $session, $res, $options) = @_;

    my $cookie = bake_cookie(
        $self->session_key, {
            value => $self->_sss->encode( $session, $options->{expires} ),
            %$options,
        }
    );
    Plack::Util::header_push($res->[1], 'Set-Cookie', $cookie);
}

1;

