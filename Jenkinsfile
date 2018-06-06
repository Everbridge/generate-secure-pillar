pipeline {
  agent any
  stages {
    stage('git') {
      steps {
        git(url: 'https://github.com/Everbridge/generate-secure-pillar.git', branch: 'jenkinstest', changelog: true, poll: true)
      }
    }
    stage('build') {
      steps {
        sh '''ls -la
'''
      }
    }
  }
}