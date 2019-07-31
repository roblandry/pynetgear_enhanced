from setuptools import setup

with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
      name='pynetgear_enhanced',
      version='0.2.2',
      description='Access Netgear routers using their SOAP API',
      long_description=long_description,
      long_description_content_type="text/markdown",
      url='http://github.com/roblandry/pynetgear_enhanced',
      download_url='http://github.com/roblandry/pynetgear_enhanced/archive/v0.2.2.tar.gz',
      author='Rob Landry',
      author_email='rob@landry.me',
      license='MIT',
      install_requires=['requests>=2.0'],
      packages=['pynetgear_enhanced'],
      zip_safe=True
)
