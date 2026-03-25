pipeline {
    agent any
    
    stages {
        stage('Security Scan') {
            steps {
                sh 'pip install pysec'
                sh 'pysec scan . --format json --output pysec-report.json'
            }
            post {
                always {
                    archiveArtifacts artifacts: 'pysec-report.json', allowEmptyArchive: true
                }
            }
        }
        
        stage('SBOM Generation') {
            steps {
                sh 'pip install pysec'
                sh 'python -c "from pysec.sbom import generate_sbom_json; print(generate_sbom_json())" > sbom.json'
            }
            post {
                always {
                    archiveArtifacts artifacts: 'sbom.json', allowEmptyArchive: true
                }
            }
        }
    }
    
    post {
        always {
            cleanWs()
        }
    }
}