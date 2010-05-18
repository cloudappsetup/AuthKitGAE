from setuptools import setup, find_packages
import sys, os

version = '0.1'

setup(name='AuthKitGAE',
      version=version,
      description="Google App Engine plugin for AuthKit.",
      long_description="""\
Provides components for use with Google App Engine:\
- Authentication with GAE Users API\
- Authorization for the Datastore""",
      classifiers=[], # Get strings from http://www.python.org/pypi?%3Aaction=list_classifiers
      keywords='authkit authentication authorization google gae appengine',
      author='Mart Roosmaa',
      author_email='roosmaa@gmail.com',
      url='http://www.roosmaa.net/',
      license='MIT',
      packages=find_packages(exclude=['ez_setup', 'examples', 'tests']),
      include_package_data=True,
      zip_safe=True,
      install_requires=[
          # -*- Extra requirements: -*-
          "AuthKit>=0.4,<=0.5",
      ],
      entry_points="""
      # -*- Entry points: -*-
      [authkit.method]
      google=authkit_gae.authenticate:make_handler
      """,
      )
