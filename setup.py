

import os
import sys
import info
from setuptools import setup, find_packages
basedir = os.path.dirname(os.path.abspath(__file__))


long_description = None
with open(os.path.join(basedir, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

packages = ['nnc','services', 'utils']

setup(
    name='nnc',
    version=info.version,
    author='Xuanfq',
    author_email='2624208682@qq.com',
    license='Apache License 2.0',
    url='https://github.com/Xuanfq/network-node-connector',
    description='A cross node connection and communication tool for a network node.',
    long_description=long_description,
    long_description_content_type='text/markdown',
    packages=packages,
    py_modules=['nnc'],
    entry_points={
        'console_scripts': [
            'nnc = nncli:main',
        ]
    },
    classifiers=[  # https://pypi.org/pypi?%3Aaction=list_classifiers
        # The period of development
        #   3 - Alpha
        #   4 - Beta
        #   5 - Production/Stable
        'Development Status :: 3 - Alpha',
        # Target users for development
        'Intended Audience :: Developers :: DevOps',
        # Topic
        'Topic :: Software Development :: DevOps Tools',
        # License
        'License :: OSI Approved :: Apache License 2.0',
        # Python Version
        'Programming Language :: Python :: 3.9',
    ],
    keywords=['nnc', 'network', 'node', 'topology'],
)