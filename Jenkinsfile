pipeline {
  agent {
    dockerfile {
      filename 'Dockerfile'
    }

  }
  stages {
    stage('git') {
      steps {
        git(url: 'https://github.com/Everbridge/generate-secure-pillar.git', branch: 'jenkinstest', changelog: true, poll: true)
      }
    }
    stage('build') {
      agent {
        dockerfile {
          filename 'Dockerfile'
        }

      }
      steps {
        sh '''make clean
make deps
make check
make test
'''
      }
    }
  }
}