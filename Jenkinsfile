pipeline {
  agent {
    docker {
      image 'golang:latest'
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
        sh '''apt-get install -y make
go get -u github.com/golang/dep/cmd/dep
go get -u github.com/alecthomas/gometalinter
gometalinter --install
dep ensure
make deps
make check
make test
'''
      }
    }
  }
}