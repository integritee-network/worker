pipeline {
  agent {
    docker {
      image 'scssubstratee/substratee_dev:18.04-2.9.1-1.1.2'
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
    stage('Information') {
      steps {
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
    stage('Archive build output') {
      steps {
        archiveArtifacts artifacts: 'bin/enclave.signed.so, bin/substratee-*', caseSensitive: false, fingerprint: true, onlyIfSuccessful: true
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
