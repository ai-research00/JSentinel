pipeline {
    agent any

    tools {
        nodejs 'node18'
    }

    stages {
        stage('Setup') {
            steps {
                sh 'npm ci'
            }
        }
        
        stage('Security Scan') {
            steps {
                script {
                    try {
                        sh 'npx jsentinel scan --ci --format sarif --output-file security-report.sarif'
                    } catch (err) {
                        unstable(message: "Security issues found")
                        currentBuild.result = 'UNSTABLE'
                    }
                }
            }
        }
    }

    post {
        always {
            recordIssues(
                tool: sarif(pattern: 'security-report.sarif'),
                qualityGates: [[threshold: 1, type: 'TOTAL', unstable: true]],
                healthy: 0,
                unhealthy: 1
            )
            
            archiveArtifacts(
                artifacts: 'security-report.sarif',
                fingerprint: true
            )
        }
    }
}
