from setuptools import setup

setup(name='pynetgear_enhanced',
      version='0.1.0',
      description='Access Netgear routers using their SOAP API',
      url='http://github.com/roblandry/pynetgear_enhanced',
      download_url='http://github.com/roblandry/pynetgear_enhanced/archive/v0.1.1.tar.gz',
      author='Rob Landry',
      author_email='rob@landry.me',
      license='MIT',
      description = 'Library to interact with Netgear Routers using SOAP',
      install_requires=['requests>=2.0'],
      packages=['pynetgear_enhanced'],
      zip_safe=True)
