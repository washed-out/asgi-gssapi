"""
ASGI-GSSAPI
-------------

Provides Kerberos authentication support for ASGI applications

Links
`````

* `documentation <https://asgi-gssapi.readthedocs.org/en/latest/>`_
* `development version
  <http://github.com/washed-out/asgi-gssapi/zipball/master#egg=asgi-gssapi-dev>`_

"""

import os
import re
from setuptools import setup

lib = os.path.join(os.path.dirname(__file__), "asgi_gssapi.py")
with open(lib) as fh:
    version = re.search(r"""__version__ = ["'](.*?)["']""", fh.read()).group(1)

setup(name='ASGI-GSSAPI',
      version=version,
      url='https://github.com/washed-out/asgi-gssapi',
      license='BSD-3-Clause',
      author='Washed Out',
      author_email='washed.out@outlook.com',
      description='GSSAPI Kerberos authentication support in ASGI Middleware',
      long_description=__doc__,
      py_modules=['asgi_kerberos'],
      zip_safe=False,
      include_package_data=True,
      package_data={'': ['LICENSE', 'AUTHORS']},
      platforms='any',
      install_requires=['gssapi >= 1.7.0'],
      classifiers=['Development Status :: 4 - Beta',
                   'Environment :: Web Environment',
                   'Intended Audience :: Developers',
                   'License :: OSI Approved :: BSD License',
                   'Operating System :: OS Independent',
                   'Programming Language :: Python',
                   'Programming Language :: Python :: 3',
                   'Topic :: Internet :: WWW/HTTP',
                   'Topic :: Software Development :: Libraries :: Python Modules'],
      test_suite='test_asgi_gssapi',
      tests_require=['pytest-asyncio', 'async-asgi-testclient', 'mock'])
