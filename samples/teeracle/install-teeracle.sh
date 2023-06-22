#!/bin/env bash

namespace=teeracle
helm uninstall -n $namespace teeracle

helm install -f ./kubernetes/values.yaml teeracle ./kubernetes --create-namespace -n $namespace

