pipeline {
  agent {
    docker {
      image 'scssubstratee/substratee_dev:18.04-2.9.1-1.1.2'
      args '''
        -u root
        --privileged
        -e SGX_SDK=/opt/sgxsdk
        -e PATH="$PATH:${SGX_SDK}/bin:${SGX_SDK}/bin/x64:/root/.cargo/bin"
        -e PKG_CONFIG_PATH="${PKG_CONFIG_PATH}:${SGX_SDK}/pkgconfig"
        -e LD_LIBRARY_PATH="${LD_LIBRARY_PATH}:${SGX_SDK}/sdk_libs"
      '''
    }
  }
  options {
    timeout(time: 2, unit: 'HOURS')
    buildDiscarder(logRotator(numToKeepStr: '14'))
  }
  stages {
    stage('Information') {
      steps {
      // atm the rust version is not up do date in the docker, therefore this is needed
        sh './ci/install_rust.sh'
        sh 'cargo --version'
        sh 'rustup show'
        sh 'env'
      }
    }
    stage('Build') {
      steps {
        sh 'make'
      }
    }
    stage('Test') {
      steps {
        sh 'cd client  && cargo test 2>&1 | tee ${WORKSPACE}/test_client.log'
        sh 'cd worker  && cargo test 2>&1 | tee ${WORKSPACE}/test_worker.log'
        sh 'cd enclave && cargo test 2>&1 | tee ${WORKSPACE}/test_enclave.log'
      }
    }
    stage('Clippy') {
      steps {
        sh 'cargo clean'
        catchError(buildResult: 'SUCCESS', stageResult: 'FAILURE') {
          sh 'cd client  && cargo +nightly-2020-04-07 clippy 2>&1 | tee ${WORKSPACE}/clippy_client.log'
        }
        catchError(buildResult: 'SUCCESS', stageResult: 'FAILURE') {
          sh 'cd worker  && cargo +nightly-2020-04-07 clippy 2>&1 | tee ${WORKSPACE}/clippy_worker.log'
        }
        catchError(buildResult: 'SUCCESS', stageResult: 'FAILURE') {
          sh 'cd enclave && cargo +nightly-2020-04-07 clippy 2>&1 | tee ${WORKSPACE}/clippy_enclave.log'
        }
      }
    }
    stage('Formatter') {
      steps {
        catchError(buildResult: 'SUCCESS', stageResult: 'SUCCESS') {
          sh 'cargo fmt -- --check > ${WORKSPACE}/fmt.log'
        }
      }
    }
    stage('Results') {
      steps {
        recordIssues(
          aggregatingResults: true,
          enabledForFailure: true,
          qualityGates: [[threshold: 1, type: 'TOTAL', unstable: true]],
          tools: [
              cargo(
                pattern: 'build_*.log',
                reportEncoding: 'UTF-8'
              ),
              groovyScript(
                parserId:'clippy-warnings',
                pattern: 'clippy_*.log',
                reportEncoding: 'UTF-8'
              ),
              groovyScript(
                parserId:'clippy-errors',
                pattern: 'clippy_*.log',
                reportEncoding: 'UTF-8'
              )
          ]
        )
        catchError(buildResult: 'SUCCESS', stageResult: 'SUCCESS') {
                  sh './ci/check_fmt_log.sh'
        }
      }
    }
    stage('Archive build output') {
      steps {
        archiveArtifacts artifacts: '*.log'
      }
    }
  }
  post {
    unsuccessful {
        emailext (
          subject: "Jenkins Build '${env.JOB_NAME} [${env.BUILD_NUMBER}]' is ${currentBuild.currentResult}",
          body: "${env.JOB_NAME} build ${env.BUILD_NUMBER} is ${currentBuild.currentResult}\n\nMore info at: ${env.BUILD_URL}",
          to: "${env.RECIPIENTS_SUBSTRATEE}"
        )
    }
    always {
      cleanWs()
    }
  }
}
