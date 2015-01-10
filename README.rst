BitShares proxy
---------------

This is a simple script that acts as an RPC proxy to the BitShares client
and provides simple access control to it, allowing to restrict access to
certain methods of the client only in a flexible way.

If you like this tool, please vote for `my
delegate <http://digitalgaia.io/btstools.html>`__ to support further
development, and feel free to visit my page for other delegate proposals
at `digitalgaia.io <http://digitalgaia.io>`__. Thanks!


Install
=======

To install, run::

    $ pip install bts_proxy

preferably (but not required) in a virtualenv.


Running the proxy
=================

Just run the ``bts-proxy`` script on the command line.

Configuration file with listening port and users/passwords alongside with
allowed methods can be found in the same data dir as the one for the BitShares
client. Config file is named ``proxy.json``, and will be created automatically
the first time you run ``bts-proxy`` if it doesn't exist yet.

You can specify a different data dir than the default one for the BitShares client
as the first argument to the ``bts-proxy`` script, e.g.::

    $ bts-proxy ~/.BitShares


Configuration file format
=========================

The configuration file is a simple JSON file, looking like this::

    {
        "port": 5681,

        "users": [
            {
                "name": "username",
                "password": "secret-password",
                "methods_allowed": ["*"]
            }
        ]
    }

``port`` is the port number on which the proxy will be listening. Make sure
to use a different port than the one on which the BitShares client is listening!

``users`` is a list of objects containing the following fields:

* ``name``: the name of the user
* ``password``: the password for that user
* ``methods_allowed``: the list of methods allowed. You can used shell-like
  pattern matching here (eg: ``"wallet_*"`` will allow all methods starting
  with ``"wallet_"``)
* ``methods_forbidden`` *(optional)*: the list of forbidden methods. You can also use
  shell-like pattern matching here.

Note that by default, methods are forbidden, so the proxy will allow you to
call a method **if and only if** it appears in the ``methods_allowed`` field
and **not** in the ``methods_forbidden`` field.

Security best practices
=======================

It is highly recommended to run both the BitShares client and the RPC proxy as
their own separate user, rather than your common one, and to restrict read access to
the BitShares client data dir to only this user.

This should come by default with BitShares >= 0.5.0, otherwise you can do the
following::

    $ chmod 700 ~/.BitShares
