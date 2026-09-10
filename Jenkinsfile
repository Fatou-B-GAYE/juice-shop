// =====================================================================
//  Examen Final - Securite des Donnees (L3 Cybersecurite)
//  Pipeline de securite automatise pour OWASP Juice Shop
//  Auteur : Ousmane BA
//
//  Version ajustee a l'environnement Docker Desktop :
//   - les scans tournent dans des conteneurs (--volumes-from) : pas
//     besoin d'installer Node/outils dans Jenkins
//   - aucune dependance a un plugin fragile (pas de publishHTML)
//   - notification email tolerante (n'echoue jamais le build)
//  Controles : SCA (npm audit) - Secret Detection (Gitleaks)
//              SAST (Semgrep)  - DAST (OWASP ZAP, non bloquant)
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
        REPORTS_DIR  = 'reports'
        MAX_CRITICAL = '0'          // seuil du security gate
        NOTIFY_EMAIL = 'ousmanhabsaba@gmail.com'
    }

    stages {

        // ---------------- 1. CHECKOUT ----------------
        stage('1. Checkout') {
            steps {
                echo '=== Recuperation du code source ==='
                checkout scm
                sh 'mkdir -p ${REPORTS_DIR}'
                sh 'git log -1 --pretty=format:"Commit: %H%nAuteur: %an%nDate: %ad%nMessage: %s" | tee ${REPORTS_DIR}/00-commit-info.txt'
            }
        }

        // ---------------- 2. SECURITY ANALYSIS (parallele) ----------------
        stage('2. Security Analysis') {
            parallel {

                stage('SCA - npm audit') {
                    steps {
                        echo '=== SCA : analyse des dependances (npm audit) ==='
                        // npm audit lit package-lock.json -> pas besoin de npm install
                        sh '''
                            docker run --rm --volumes-from $(hostname) -w ${WORKSPACE} node:20 \
                              sh -c "npm audit --json > ${REPORTS_DIR}/sca-npm-audit.json 2>/dev/null || true; \
                                     npm audit        > ${REPORTS_DIR}/sca-npm-audit.txt  2>/dev/null || true"
                            echo '--- Resume SCA ---'
                            tail -20 ${REPORTS_DIR}/sca-npm-audit.txt || true
                        '''
                    }
                }

                stage('Secrets - Gitleaks') {
                    steps {
                        echo '=== Secret Detection : Gitleaks ==='
                        sh '''
                            docker run --rm --volumes-from $(hostname) -w ${WORKSPACE} \
                              zricethezav/gitleaks:latest detect \
                              --source . --config .gitleaks.toml \
                              --report-format json --report-path ${REPORTS_DIR}/secrets-gitleaks.json \
                              --redact --no-git --exit-code 0 --verbose \
                              2>&1 | tee ${REPORTS_DIR}/secrets-gitleaks.txt || true
                        '''
                    }
                }

                stage('SAST - Semgrep') {
                    steps {
                        echo '=== SAST : analyse statique (Semgrep) ==='
                        sh '''
                            docker run --rm --volumes-from $(hostname) -w ${WORKSPACE} \
                              semgrep/semgrep:latest semgrep scan \
                              --config security-config/semgrep-rules.yml \
                              --json --output ${REPORTS_DIR}/sast-semgrep.json \
                              --metrics=off --no-git-ignore \
                              routes lib models frontend 2>&1 | tail -40 \
                              | tee ${REPORTS_DIR}/sast-semgrep.txt || true
                        '''
                    }
                }
            }
        }

        // ---------------- 3. DAST (non bloquant) ----------------
        stage('3. DAST - OWASP ZAP') {
            steps {
                echo '=== DAST : scan dynamique ZAP sur l application en cours d execution ==='
                // juice-shop tourne deja sur l hote (port 3000) -> host.docker.internal
                catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
                    sh '''
                        docker run --rm --volumes-from $(hostname) -w ${WORKSPACE} \
                          ghcr.io/zaproxy/zaproxy:stable zap-baseline.py \
                          -t http://host.docker.internal:3000 \
                          -J ${REPORTS_DIR}/dast-zap.json \
                          -r ${REPORTS_DIR}/dast-zap.html \
                          -I -m 2 2>&1 | tee ${REPORTS_DIR}/dast-zap.txt || true
                    '''
                }
            }
        }

        // ---------------- 4. REPORT + SECURITY GATE ----------------
        stage('4. Report + Security Gate') {
            steps {
                echo '=== Consolidation et application du seuil de securite ==='
                sh '''
                    CRIT=$(grep -oE "\\"critical\\":[0-9]+" ${REPORTS_DIR}/sca-npm-audit.json | head -1 | cut -d: -f2)
                    HIGH=$(grep -oE "\\"high\\":[0-9]+"     ${REPORTS_DIR}/sca-npm-audit.json | head -1 | cut -d: -f2)
                    SECRETS=$(grep -oc "\\"RuleID\\"" ${REPORTS_DIR}/secrets-gitleaks.json 2>/dev/null || echo 0)

                    {
                      echo "==================================================="
                      echo " RAPPORT DE SECURITE CONSOLIDE - BUILD #${BUILD_NUMBER}"
                      echo " Date : $(date)"
                      echo "==================================================="
                      echo "[SCA]     Dependances critiques : ${CRIT:-0}"
                      echo "[SCA]     Dependances elevees   : ${HIGH:-0}"
                      echo "[SECRETS] Secrets detectes      : ${SECRETS:-0}"
                      echo "[SAST]    Voir reports/sast-semgrep.txt"
                      echo "[DAST]    Voir reports/dast-zap.html"
                      echo "Seuil applique : CRITICAL <= ${MAX_CRITICAL}"
                    } | tee ${REPORTS_DIR}/SUMMARY.txt

                    echo "${CRIT:-0}" > ${REPORTS_DIR}/.crit
                '''
                script {
                    def crit = readFile("${REPORTS_DIR}/.crit").trim()
                    if ((crit ?: '0').toInteger() > env.MAX_CRITICAL.toInteger()) {
                        error "SECURITY GATE : ECHEC - ${crit} vulnerabilite(s) critique(s) > seuil (${env.MAX_CRITICAL}). Deploiement BLOQUE."
                    }
                }
            }
        }
    }

    // ---------------- POST : archivage + notification ----------------
    post {
        always {
            archiveArtifacts artifacts: 'reports/**', allowEmptyArchive: true, fingerprint: true
            script {
                try {
                    emailext(
                        subject: "[${currentBuild.currentResult}] Pipeline securite ${APP_NAME} - Build #${BUILD_NUMBER}",
                        body: """<h3>Pipeline de securite - ${APP_NAME}</h3>
                                 <p><b>Resultat :</b> ${currentBuild.currentResult}</p>
                                 <p><b>Build :</b> #${BUILD_NUMBER} - duree ${currentBuild.durationString}</p>
                                 <p><b>Console :</b> <a href="${BUILD_URL}console">${BUILD_URL}console</a></p>
                                 <p>Rapports SCA / SAST / DAST / Secrets en piece jointe.</p>""",
                        mimeType: 'text/html',
                        to: env.NOTIFY_EMAIL,
                        attachmentsPattern: 'reports/SUMMARY.txt,reports/sca-npm-audit.txt,reports/secrets-gitleaks.txt'
                    )
                } catch (e) {
                    echo "Notification email non envoyee (SMTP non configure) : ${e.message}"
                }
            }
        }
        failure { echo 'SECURITY GATE FRANCHI : deploiement BLOQUE.' }
        success { echo 'Tous les controles de securite sont passes.' }
    }
}
