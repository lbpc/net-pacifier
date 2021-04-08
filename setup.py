import sys
from setuptools import setup

MAJOR_VERSION = '1'
MINOR_VERSION = '0'
MICRO_VERSION = '0'
VERSION = "{}.{}.{}".format(MAJOR_VERSION, MINOR_VERSION, MICRO_VERSION)

setup(name='pacifier',
      version=VERSION,
      description="Скрипт для анализа логов и управления фильтрами",
      url='https://gitlab.intr/net/pacifier',
      author='sidorov',
      author_email='sidorov@majordomo.ru',
      license='GPLv3',
      packages=['pacifier'],
      classifiers=[
          'Environment :: Console',
          'Intended Audience :: End Users/Desktop',
          'Intended Audience :: Developers',
          'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
          'Operating System :: MacOS :: MacOS X',
          'Operating System :: Unix',
          'Operating System :: POSIX',
          'Programming Language :: Python',
          'Programming Language :: Python :: 3.6',
          'Development Status :: 5 - Production/Stable',
          'Topic :: Office/Business'
      ],
      zip_safe=False,
      entry_points={'console_scripts': ['pacifier = pacifier.__main__:main']},
      platforms='any')
