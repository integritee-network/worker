pipeline {
  agent {
    node {
      label 'rust&&sgx'
    }
  }
  options {
    timeout(time: 2, unit: 'HOURS')
    buildDiscarder(logRotator(numToKeepStr: '14'))
  }
  stages {
    stage('Environment') {
      steps {
        sh './ci/install_rust.sh'
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
          sh 'cd client  && cargo +nightly-2020-03-12 clippy 2>&1 | tee ${WORKSPACE}/clippy_client.log'
        }
        catchError(buildResult: 'SUCCESS', stageResult: 'FAILURE') {
          sh 'cd worker  && cargo +nightly-2020-03-12 clippy 2>&1 | tee ${WORKSPACE}/clippy_worker.log'
        }
        catchError(buildResult: 'SUCCESS', stageResult: 'FAILURE') {
          sh 'cd enclave && cargo +nightly-2020-03-12 clippy 2>&1 | tee ${WORKSPACE}/clippy_enclave.log'
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
