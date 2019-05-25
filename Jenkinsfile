pipeline {
  agent {
    node {
      label 'rust&&sgx'
    }
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
        echo 'Stage TEST'
        echo 'Not implemented yet'
      }
    }
    stage('Lint') {
      steps {
        sh 'cd client  && cargo +nightly-2019-05-21 clippy --message-format short 2>&1 | tee ../clippy_client.log'
        sh 'cd worker  && cargo +nightly-2019-05-21 clippy --message-format short 2>&1 | tee ../clippy_worker.log'
        sh 'cd enclave && cargo +nightly-2019-05-21 clippy --message-format short 2>&1 | tee ../clippy_enclave.log'
      }
    }
    stage('CheckLog') {
      steps {
        echo 'Checking the logs'
        script {
          try {
            sh './ci/check_logs.sh'
          }
          catch (exc) {
            echo "Got value ${exc}"
            currentBuild.result = 'UNSTABLE'
          }
        }
      }
      post {
        unstable {
          emailext attachmentsPattern: '*.log',
          body: "Mr. Jenkins and Mrs. Clippy have bad news for you:\n${env.JOB_NAME}#${env.BUILD_NUMBER} is ${currentBuild.currentResult}\n\nWarnings or errors have been found by Mrs. Clippy.\n\nCheck console output at ${env.BUILD_URL} to view the results.",
          subject: "Bad news for build ${env.JOB_NAME}",
          to: "${env.RECIPIENTS_SUBSTRATEE}"
        }
      }
    }
    stage('Archive build output') {
      steps {
        archiveArtifacts artifacts: '*.log'
      }
    }
  }
}
