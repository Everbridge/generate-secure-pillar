pipeline {
  agent {
    docker {
      image 'ubuntu:latest'
    }

  }
  stages {
    stage('') {
      steps {
        git(url: 'https://github.com/Everbridge/generate-secure-pillar.git', branch: 'master', changelog: true, poll: true)
      }
    }
  }
  environment {
    JenkinsBuild = 'True'
  }
}