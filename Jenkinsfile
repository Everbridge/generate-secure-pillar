pipeline {
  agent any
  stages {
    stage('error') {
      steps {
        git(url: 'https://github.com/Everbridge/generate-secure-pillar.git', branch: 'master', changelog: true, poll: true)
      }
    }
  }
}