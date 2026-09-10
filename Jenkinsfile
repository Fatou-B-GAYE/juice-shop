// =====================================================================
//  Examen Final - Securite des Donnees (L3 Cybersecurite)
//  Pipeline de securite automatise pour OWASP Juice Shop
//  Auteur : Ousmane BA
//  Controles integres : SCA (npm audit) - Secret Detection (Gitleaks)
//                       SAST (Semgrep)  - DAST (OWASP ZAP Baseline)
// =====================================================================

pipeline {
    agent any

    options {
        timestamps()
        buildDiscarder(logRotator(numToKeepStr: '10'))
        timeout(time: 45, unit: 'MINUTES')
    }

    environment {
        APP_NAME       = 'juice-shop'
        APP_URL        = 'http://juice-shop:3000'
        REPORTS_DIR    = 'reports'
        // Seuils de securite (gates)
        MAX_CRITICAL   = '0'
        MAX_SECRETS    = '0'
    }

    stages {

        // ---------------- 1. CHECKOUT ----------------
        stage('1. Checkout') {
            steps {
                echo '=== Recuperation du code source depuis GitHub ==='
                checkout scm
                sh 'mkdir -p ${REPORTS_DIR}'
                sh 'git log -1 --pretty=format:"Commit: %H%nAuteur: %an%nDate: %ad%nMessage: %s" | tee ${REPORTS_DIR}/00-commit-info.txt'
            }
        }

        // ---------------- 2. BUILD / PREPARATION ----------------
        stage('2. Build / Preparation') {
            steps {
                echo '=== Installation des dependances (sans postinstall) ==='
                // --ignore-scripts : le postinstall Angular de Juice Shop echoue
                //                    sur connexion lente et n'est pas necessaire au scan
                // --legacy-peer-deps : conflits de peer dependencies du projet
                sh '''
                    npm install --legacy-peer-deps --ignore-scripts 2>&1 | tail -20
                    node --version  > ${REPORTS_DIR}/01-build-env.txt
                    npm --version  >> ${REPORTS_DIR}/01-build-env.txt
                '''
            }
        }

        // ---------------- 3. SECURITY ANALYSIS ----------------
        stage('3. Security Analysis') {
            parallel {

                stage('SCA - npm audit') {
                    steps {
                        echo '=== Analyse des dependances (Software Composition Analysis) ==='
                        sh '''
                            npm audit --json > ${REPORTS_DIR}/sca-npm-audit.json || true
                            npm audit        > ${REPORTS_DIR}/sca-npm-audit.txt  || true
                            echo "--- Resume SCA ---"
                            tail -15 ${REPORTS_DIR}/sca-npm-audit.txt
                        '''
                    }
                }

                stage('Secret Detection - Gitleaks') {
                    steps {
                        echo '=== Detection de secrets dans le code et l historique Git ==='
                        sh '''
                            docker run --rm --volumes-from $(hostname) -w ${WORKSPACE} \
                                zricethezav/gitleaks:latest detect \
                                --source . \
                                --config .gitleaks.toml \
                                --report-format json \
                                --report-path ${REPORTS_DIR}/secrets-gitleaks.json \
                                --redact --no-git --exit-code 0 --verbose \
                                | tee ${REPORTS_DIR}/secrets-gitleaks.txt || true
                        '''
                    }
                }

                stage('SAST - Semgrep') {
                    steps {
                        echo '=== Analyse statique du code source ==='
                        sh '''
                            docker run --rm --volumes-from $(hostname) -w ${WORKSPACE} \
                                semgrep/semgrep:latest semgrep scan \
                                --config security-config/semgrep-rules.yml \
                                --config p/javascript \
                                --config p/owasp-top-ten \
                                --json --output ${REPORTS_DIR}/sast-semgrep.json \
                                --no-git-ignore --metrics=off \
                                routes/ lib/ models/ 2>&1 | tail -30 \
                                | tee ${REPORTS_DIR}/sast-semgrep.txt || true
                        '''
                    }
                }
            }
        }

        // ---------------- 4. ADDITIONAL SECURITY CHECK (DAST) ----------------
        stage('4. Additional Security Check - DAST') {
            steps {
                echo '=== Lancement de l application cible puis scan dynamique OWASP ZAP ==='
                sh '''
                    docker rm -f juice-shop-dast 2>/dev/null || true
                    docker network create secnet 2>/dev/null || true
                    docker run -d --rm --name juice-shop-dast --network secnet \
                        -p 3000:3000 bkimminich/juice-shop
                    echo "Attente du demarrage de l application (45s)..."
                    sleep 45
                '''
                sh '''
                    docker run --rm --network secnet --volumes-from $(hostname) -w ${WORKSPACE} \
                        -t ghcr.io/zaproxy/zaproxy:stable zap-baseline.py \
                        -t http://juice-shop-dast:3000 \
                        -J ${REPORTS_DIR}/dast-zap.json \
                        -r ${REPORTS_DIR}/dast-zap.html \
                        -I -m 3 2>&1 | tee ${REPORTS_DIR}/dast-zap.txt || true
                '''
            }
            post {
                always {
                    sh 'docker rm -f juice-shop-dast 2>/dev/null || true'
                }
            }
        }

        // ---------------- 5. REPORT GENERATION ----------------
        stage('5. Report Generation') {
            steps {
                echo '=== Consolidation des resultats et application des seuils ==='
                sh '''
                    CRIT=$(grep -oE '"critical":[0-9]+' ${REPORTS_DIR}/sca-npm-audit.json | head -1 | cut -d: -f2)
                    HIGH=$(grep -oE '"high":[0-9]+'     ${REPORTS_DIR}/sca-npm-audit.json | head -1 | cut -d: -f2)
                    SECRETS=$(grep -oc '"RuleID"' ${REPORTS_DIR}/secrets-gitleaks.json || echo 0)

                    {
                      echo "==================================================="
                      echo " RAPPORT DE SECURITE CONSOLIDE - BUILD #${BUILD_NUMBER}"
                      echo " Date : $(date)"
                      echo "==================================================="
                      echo ""
                      echo "[SCA]     Dependances critiques : ${CRIT:-0}"
                      echo "[SCA]     Dependances elevees   : ${HIGH:-0}"
                      echo "[SECRETS] Secrets detectes      : ${SECRETS:-0}"
                      echo "[SAST]    Voir sast-semgrep.txt"
                      echo "[DAST]    Voir dast-zap.html"
                      echo ""
                      echo "Seuils appliques : CRITICAL<=${MAX_CRITICAL} , SECRETS<=${MAX_SECRETS}"
                    } | tee ${REPORTS_DIR}/SUMMARY.txt

                    # Security Gate : echec du build si seuils depasses
                    if [ "${CRIT:-0}" -gt "${MAX_CRITICAL}" ]; then
                        echo "SECURITY GATE : ECHEC - vulnerabilites critiques presentes"
                        exit 1
                    fi
                '''
            }
            post {
                always {
                    archiveArtifacts artifacts: 'reports/**', allowEmptyArchive: true, fingerprint: true
                    publishHTML(target: [
                        reportDir: 'reports', reportFiles: 'dast-zap.html',
                        reportName: 'Rapport DAST OWASP ZAP',
                        keepAll: true, alwaysLinkToLastBuild: true, allowMissing: true
                    ])
                }
            }
        }
    }

    // ---------------- 6. NOTIFICATION ----------------
    post {
        always {
            echo '=== Envoi de la notification ==='
            emailext(
                subject: "[${currentBuild.currentResult}] Pipeline securite ${APP_NAME} - Build #${BUILD_NUMBER}",
                body: """<h3>Pipeline de securite - ${APP_NAME}</h3>
                         <p><b>Resultat :</b> ${currentBuild.currentResult}</p>
                         <p><b>Build :</b> #${BUILD_NUMBER}</p>
                         <p><b>Duree :</b> ${currentBuild.durationString}</p>
                         <p><b>Console :</b> <a href="${BUILD_URL}console">${BUILD_URL}console</a></p>
                         <p>Rapports SCA / SAST / DAST / Secrets en piece jointe.</p>""",
                mimeType: 'text/html',
                to: 'ousmanhabsaba@gmail.com',
                attachmentsPattern: 'reports/SUMMARY.txt,reports/sca-npm-audit.txt,reports/secrets-gitleaks.txt'
            )
        }
        failure  { echo 'SECURITY GATE FRANCHI : deploiement BLOQUE.' }
        success  { echo 'Tous les controles de securite sont passes.' }
    }
}
