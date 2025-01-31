# Selenium tests

For more information see https://www.mediawiki.org/wiki/Selenium

## Setup

These Selenium tesets are intended to be run within the mediawiki-quickstart
environment. This is necessary, since mediawiki-quickstart creates and
configures a Keycloak container to operate as the identity provider.

Install mediawiki-quickstart from:

    https://gitlab.wikimedia.org/repos/test-platform/mediawiki-quickstart

Then, run:

    ./fresh_install
    ./install extensions/OpenIDConnect

## Run all specs

    ./run_component_selenium_tests extensions/OpenIDConnect
