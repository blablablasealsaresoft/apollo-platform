@Library('apollo-shared-lib') _

def deploymentEnv = params.get('ENV', 'staging')

declarativePipeline {
  options {
    disableConcurrentBuilds()
  }
  stages {
    stage('Checkout') { steps { checkout scm } }
    stage('Build surveillance images') {
      steps {
        sh 'docker compose -f docker/surveillance/docker-compose.yml build'
      }
    }
    stage('Device emulation tests') {
      steps {
        sh './infrastructure/ci-cd/scripts/surveillance-tests.sh'
      }
    }
    stage('Gate review') {
      steps {
        input message: "Promote ${deploymentEnv}?", ok: 'Deploy'
      }
    }
    stage('Deploy to cluster') {
      steps {
        sh "kubectl --kubeconfig kubeconfigs/${deploymentEnv} apply -f infrastructure/kubernetes"
      }
    }
  }
}
