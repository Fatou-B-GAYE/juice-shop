// =====================================================================
//  Examen Final - Securite des Donnees (L3 Cybersecurite)
//  Pipeline de securite automatise pour OWASP Juice Shop
//  Auteur : Ousmane BA
//
//  Version ajustee a Docker Desktop (scans conteneurises via
//  --volumes-from). Sans code Groovy fragile : le security gate est
//  calcule en shell. Controles : SCA (npm audit) - Secrets (Gitleaks)
//  - SAST (Semgrep) - DAST (OWASP ZAP, non bloquant).
// =====================================================================

pipeline {
    agent any

    options {
        timestamps()
        timeout(time: 40, unit: 'MINUTES')
        buildDiscarder(logRotator(numToKeepStr: '10'))
    }

    environment {
        APP_NAME     = 'juice-shop'
        NOTIFY_EMAIL = 'ousmanhabsaba@gmail.com'
    }

    stages {

        // ---------------- 1. CHECKOUT ----------------
        stage('1. Checkout') {
            steps {
                echo '=== Recuperation du code source ==='
                checkout scm
                sh 'mkdir -p reports'
                sh 'git log -1 --pretty=format:"Commit: %H%nAuteur: %an%nDate: %ad%nMessage: %s" | tee reports/00-commit-info.txt'
            }
        }

        // ---------------- 2. SECURITY ANALYSIS (parallele) ----------------
        stage('2. Security Analysis') {
            parallel {

                stage('SCA - npm audit') {
                    steps {
                        echo '=== SCA : analyse des dependances (npm audit) ==='
                        sh '''
                            set +e
                            HOST=$(hostname)
                            docker run --rm --volumes-from $HOST -w "$WORKSPACE" node:20 npm audit --json > reports/sca-npm-audit.json 2>/dev/null
                            docker run --rm --volumes-from $HOST -w "$WORKSPACE" node:20 npm audit        > reports/sca-npm-audit.txt  2>/dev/null
                            echo "--- Resume SCA ---"
                            tail -n 20 reports/sca-npm-audit.txt 2>/dev/null
                            true
                        '''
                    }
                }

                stage('Secrets - Gitleaks') {
                    steps {
                        echo '=== Secret Detection : Gitleaks ==='
                        sh '''
                            HOST=$(hostname)
                            docker run --rm --volumes-from $HOST -w "$WORKSPACE" \
                              zricethezav/gitleaks:latest detect \
                              --source . --config .gitleaks.toml \
                              --report-format json --report-path reports/secrets-gitleaks.json \
                              --redact --no-git --exit-code 0 --verbose \
                              > reports/secrets-gitleaks.txt 2>&1 || true
                            tail -n 20 reports/secrets-gitleaks.txt || true
                        '''
                    }
                }

                stage('SAST - Semgrep') {
                    steps {
                        echo '=== SAST : analyse statique (Semgrep) ==='
                        sh '''
                            HOST=$(hostname)
                            docker run --rm --volumes-from $HOST -w "$WORKSPACE" \
                              semgrep/semgrep:latest semgrep scan \
                              --config security-config/semgrep-rules.yml \
                              --json --output reports/sast-semgrep.json \
                              --metrics=off --no-git-ignore \
                              routes lib models frontend \
                              > reports/sast-semgrep.txt 2>&1 || true
                            tail -n 30 reports/sast-semgrep.txt || true
                        '''
                    }
                }
            }
        }

        // ---------------- 3. DAST (non bloquant) ----------------
        stage('3. DAST - OWASP ZAP') {
            steps {
                echo '=== DAST : scan dynamique ZAP sur l application en cours d execution ==='
                catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
                    sh '''
                        HOST=$(hostname)
                        docker run --rm --volumes-from $HOST -w "$WORKSPACE" \
                          ghcr.io/zaproxy/zaproxy:stable zap-baseline.py \
                          -t http://host.docker.internal:3000 \
                          -J reports/dast-zap.json -r reports/dast-zap.html \
                          -I -m 2 > reports/dast-zap.txt 2>&1 || true
                        tail -n 20 reports/dast-zap.txt || true
                    '''
                }
            }
        }

        // ---------------- 4. REPORT + SECURITY GATE ----------------
        stage('4. Report + Security Gate') {
            steps {
                echo '=== Consolidation et application du seuil de securite ==='
                sh '''
                    CRIT=$(grep -oE "\\"critical\\":[0-9]+" reports/sca-npm-audit.json 2>/dev/null | head -1 | cut -d: -f2)
                    HIGH=$(grep -oE "\\"high\\":[0-9]+"     reports/sca-npm-audit.json 2>/dev/null | head -1 | cut -d: -f2)
                    SECRETS=$(grep -oc "RuleID" reports/secrets-gitleaks.json 2>/dev/null || echo 0)
                    CRIT=${CRIT:-0}; HIGH=${HIGH:-0}; SECRETS=${SECRETS:-0}

                    {
                      echo "==================================================="
                      echo " RAPPORT DE SECURITE CONSOLIDE - BUILD #${BUILD_NUMBER}"
                      echo " Date : $(date)"
                      echo "==================================================="
                      echo "[SCA]     Dependances critiques : ${CRIT}"
                      echo "[SCA]     Dependances elevees   : ${HIGH}"
                      echo "[SECRETS] Secrets detectes      : ${SECRETS}"
                      echo "[SAST]    Voir reports/sast-semgrep.txt"
                      echo "[DAST]    Voir reports/dast-zap.html"
                      echo "Seuils : CRITICAL=0 , SECRETS=0"
                    } | tee reports/SUMMARY.txt

                    echo ""
                    if [ "${CRIT}" -gt 0 ] || [ "${SECRETS}" -gt 0 ]; then
                        echo "SECURITY GATE : ECHEC (critiques=${CRIT}, secrets=${SECRETS}) -> DEPLOIEMENT BLOQUE"
                        exit 1
                    fi
                    echo "SECURITY GATE : OK"
                '''
            }
        }
    }

    // ---------------- POST : archivage + notification ----------------
    post {
        always {
            archiveArtifacts artifacts: 'reports/**', allowEmptyArchive: true, fingerprint: true
            script {
                try {
                    // Etape mail native de Jenkins (aucun plugin requis).
                    // Necessite un serveur SMTP configure dans
                    // Administrer Jenkins > Configuration du systeme > Notification par email.
                    mail(
                        to: env.NOTIFY_EMAIL,
                        subject: "[${currentBuild.currentResult}] Pipeline securite ${APP_NAME} - Build #${BUILD_NUMBER}",
                        body: """Pipeline de securite - ${APP_NAME}
Resultat : ${currentBuild.currentResult}
Build    : #${BUILD_NUMBER} (duree ${currentBuild.durationString})
Console  : ${BUILD_URL}console
Rapports SCA / SAST / DAST / Secrets archives dans le build."""
                    )
                    echo 'Notification email envoyee.'
                } catch (Throwable e) {
                    echo "Notification email non envoyee (SMTP non configure) : ${e.message}"
                }
            }
        }
        failure { echo 'SECURITY GATE FRANCHI : deploiement BLOQUE.' }
        success { echo 'Tous les controles de securite sont passes.' }
    }
}
