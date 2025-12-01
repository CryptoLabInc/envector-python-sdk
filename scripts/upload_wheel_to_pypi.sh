#!/usr/bin/env bash

set -e

if [ "$UPLOAD_TARGET" = "release-pypi" ]; then
    echo "🚀 Uploading to PyPI..."
    twine upload dist/*
else
    echo "🚀 Uploading to TestPyPI..."
    twine upload --repository testpypi dist/*
fi
