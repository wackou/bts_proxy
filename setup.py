#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# bts_proxy - Proxy providing RPC access control to the BitShares client
# Copyright (c) 2015 Nicolas Wack <wackou@gmail.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

from setuptools import setup, find_packages
import os.path

here = os.path.abspath(os.path.dirname(__file__))
README = open(os.path.join(here, 'README.rst')).read()
HISTORY = open(os.path.join(here, 'HISTORY.rst')).read()

VERSION = '0.1'


install_requires = ['requests']

setup_requires = []

entry_points = {
    'console_scripts': [
        'bts-proxy = bts_proxy.proxy:main'
    ],
}


args = dict(name='bts_proxy',
            version=VERSION,
            description='BitShares RPC proxy',
            long_description=README,
            # Get strings from
            # http://pypi.python.org/pypi?%3Aaction=list_classifiers
            classifiers=['Development Status :: 3 - Alpha',
                         'License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)',
                         'Operating System :: OS Independent',
                         'Programming Language :: Python :: 3',
                         'Programming Language :: Python :: 3.3',
                         'Programming Language :: Python :: 3.4',
                         ],
            keywords='BitShares RPC proxy',
            author='Nicolas Wack',
            author_email='wackou@gmail.com',
            url='https://github.com/wackou/bts_proxy',
            packages=find_packages(),
            include_package_data=True,
            install_requires=install_requires,
            setup_requires=setup_requires,
            entry_points=entry_points,
            )

setup(**args)
