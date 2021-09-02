pipeline {
  agent {
    docker {
      image 'scssubstratee/substratee_dev:1804-2.12-1.1.3-001'
      args '''
        -u root
        --privileged
      '''
    }
  }
  options {
    timeout(time: 2, unit: 'HOURS')
    buildDiscarder(logRotator(numToKeepStr: '14'))
  }
  stages {
    stage('rustup') {
      steps {
        sh './ci/install_rust.sh'
      }
    }
    stage('Information') {
      steps {
        sh 'cargo --version'
        sh 'rustup show'
        sh 'env'
      }
    }
    stage('Build') {
      steps {
        sh 'export SGX_SDK=/opt/intel/sgxsdk'
        sh 'make'
      }
    }
    stage('Archive build output') {
      steps {
        archiveArtifacts artifacts: 'bin/enclave.signed.so, bin/integritee-*', caseSensitive: false, fingerprint: true, onlyIfSuccessful: true
      }
    }
    stage('Test') {
      steps {
        sh 'cd client  && cargo test 2>&1 | tee ${WORKSPACE}/test_client.log'
        sh 'cd service  && cargo test 2>&1 | tee ${WORKSPACE}/test_server.log'
        sh 'cd enclave-runtime && cargo test 2>&1 | tee ${WORKSPACE}/test_enclave.log'
      }
    }
    stage('Clippy') {
      steps {
        sh 'cargo clean'
        catchError(buildResult: 'SUCCESS', stageResult: 'FAILURE') {
          sh 'cd client  && cargo clippy 2>&1 | tee ${WORKSPACE}/clippy_client.log'
        }
        catchError(buildResult: 'SUCCESS', stageResult: 'FAILURE') {
          sh 'cd worker  && cargo clippy 2>&1 | tee ${WORKSPACE}/clippy_worker.log'
        }
        catchError(buildResult: 'SUCCESS', stageResult: 'FAILURE') {
          sh 'cd enclave && cargo clippy 2>&1 | tee ${WORKSPACE}/clippy_enclave.log'
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
    stage('Archive logs') {
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
