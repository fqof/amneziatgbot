#!/usr/bin/env bash
#
# bot.sh — единая точка управления ботом через screen.
# Заменяет собой отдельные start.sh/stop.sh: запускает/останавливает все три
# screen-сессии (bot, webapp, miniapp) одной командой, сам определяет, что
# уже запущено, и не даёт запустить/остановить повторно.
#
# Использование:
#   ./bot.sh start    — запустить все сервисы (уже запущенные пропускаются)
#   ./bot.sh stop     — остановить все сервисы (не запущенные пропускаются)
#   ./bot.sh restart  — перезапустить все сервисы
#   ./bot.sh status   — показать текущее состояние всех сервисов
#   ./bot.sh attach <имя>  — подключиться к консоли сервиса (bot|webapp|miniapp)
#   ./bot.sh help     — показать эту справку

set -uo pipefail

# ---------------------------------------------------------------------------
# Настройки. При необходимости поменяйте под свой сервер.
# ---------------------------------------------------------------------------
APP_DIR="/wtf/bot/beta"
VENV_ACTIVATE="/root/me/bin/activate"
STARTUP_DELAY="${BOT_STARTUP_DELAY:-5}"   # секунд ожидания перед стартом (сеть/диск после ребута)
STOP_TIMEOUT="${BOT_STOP_TIMEOUT:-10}"    # сколько секунд ждать штатной остановки каждой screen-сессии
LOG_DIR="${APP_DIR}/logs"

# Сервисы: имя screen-сессии → команда запуска.
SERVICE_NAMES=(bot webapp miniapp)
declare -A SERVICE_CMD=(
  [bot]="python bot.py"
  [webapp]="python web_service.py"
  [miniapp]="python miniapp.py"
)
declare -A SERVICE_FILE=(
  [bot]="bot.py"
  [webapp]="web_service.py"
  [miniapp]="miniapp.py"
)

SCRIPT_NAME="$(basename "$0")"

# ---------------------------------------------------------------------------
# Вывод
# ---------------------------------------------------------------------------
info() { echo "[инфо]   $*"; }
ok()   { echo "[ok]     $*"; }
warn() { echo "[внимание] $*" >&2; }
err()  { echo "[ошибка] $*" >&2; }

usage() {
  cat <<EOF
Использование: $SCRIPT_NAME {start|stop|restart|status|attach <имя>|help}

  start            запустить bot/webapp/miniapp в screen-сессиях (если ещё не запущены)
  stop             остановить все screen-сессии (если запущены)
  restart          остановить и снова запустить все сервисы
  status           показать, какие сервисы запущены
  attach <имя>     подключиться к сессии: bot | webapp | miniapp (Ctrl+A, D — отключиться)
  help             показать эту справку
EOF
}

# ---------------------------------------------------------------------------
# Проверки окружения
# ---------------------------------------------------------------------------
require_screen() {
  if ! command -v screen >/dev/null 2>&1; then
    err "команда 'screen' не найдена. Установите её, например: apt install screen"
    exit 1
  fi
}

# Точное совпадение имени сессии (а не любой сессии, чьё имя начинается так же).
is_running() {
  local name="$1"
  screen -list 2>/dev/null | grep -Eq "[0-9]+\.${name}[[:space:]]"
}

print_session_line() {
  local name="$1"
  screen -list 2>/dev/null | grep -E "[0-9]+\.${name}[[:space:]]" || true
}

# ---------------------------------------------------------------------------
# Команды для одного сервиса
# ---------------------------------------------------------------------------
start_one() {
  local name="$1"
  local cmd="${SERVICE_CMD[$name]}"
  local log_file="${LOG_DIR}/${name}.log"

  if is_running "$name"; then
    ok "'$name' уже запущен — повторный запуск не требуется."
    print_session_line "$name"
    return 0
  fi

  info "запускаю '$name' в screen..."
  screen -dmS "$name" -L -Logfile "$log_file" bash -c "cd '$APP_DIR' && source '$VENV_ACTIVATE' && exec $cmd"

  sleep 1
  if is_running "$name"; then
    ok "'$name' запущено. Подключиться: $SCRIPT_NAME attach $name  (или напрямую: screen -r $name)"
  else
    err "не удалось запустить screen-сессию '$name'. Проверьте лог: $log_file"
    return 1
  fi
}

stop_one() {
  local name="$1"

  if ! is_running "$name"; then
    info "'$name' не запущен — останавливать нечего."
    return 0
  fi

  info "останавливаю '$name'..."
  screen -S "$name" -X quit

  local waited=0
  while is_running "$name"; do
    if [[ "$waited" -ge "$STOP_TIMEOUT" ]]; then
      warn "'$name' не завершился за ${STOP_TIMEOUT}с, добиваю принудительно..."
      pkill -f "SCREEN.*${name}" 2>/dev/null || true
      sleep 1
      break
    fi
    sleep 0.5
    waited=$((waited + 1))
  done

  if is_running "$name"; then
    err "не удалось остановить '$name'. Проверьте вручную: screen -list"
    return 1
  fi

  ok "'$name' остановлено."
}

# ---------------------------------------------------------------------------
# Общие команды
# ---------------------------------------------------------------------------
do_start() {
  require_screen

  if [[ ! -d "$APP_DIR" ]]; then
    err "директория проекта не найдена: $APP_DIR"
    exit 1
  fi

  if [[ ! -f "$VENV_ACTIVATE" ]]; then
    err "виртуальное окружение не найдено: $VENV_ACTIVATE"
    exit 1
  fi

  if [[ "$STARTUP_DELAY" -gt 0 ]]; then
    info "жду ${STARTUP_DELAY}с перед запуском (даю время подняться сети/диску)..."
    sleep "$STARTUP_DELAY"
  fi

  mkdir -p "$LOG_DIR"

  local failed=0
  for name in "${SERVICE_NAMES[@]}"; do
    start_one "$name" || failed=1
  done

  if [[ "$failed" -eq 0 ]]; then
    ok "Все сервисы запущены."
  else
    err "Часть сервисов не удалось запустить, смотрите вывод выше."
    exit 1
  fi
}

do_stop() {
  require_screen

  local failed=0
  for name in "${SERVICE_NAMES[@]}"; do
    stop_one "$name" || failed=1
  done

  if [[ "$failed" -eq 0 ]]; then
    ok "Все сервисы остановлены."
  else
    err "Часть сервисов не удалось остановить, смотрите вывод выше."
    exit 1
  fi
}

do_restart() {
  info "перезапуск всех сервисов..."
  do_stop
  do_start
}

do_status() {
  require_screen
  local any_running=0
  for name in "${SERVICE_NAMES[@]}"; do
    if is_running "$name"; then
      ok "'$name' (${SERVICE_FILE[$name]}) запущен:"
      print_session_line "$name"
      any_running=1
    else
      info "'$name' (${SERVICE_FILE[$name]}) не запущен."
    fi
  done
  return 0
}

do_attach() {
  require_screen
  local name="${1:-}"

  if [[ -z "$name" ]]; then
    err "укажите сервис для подключения: bot | webapp | miniapp"
    echo
    usage
    exit 1
  fi

  if [[ -z "${SERVICE_CMD[$name]:-}" ]]; then
    err "неизвестный сервис: $name (допустимые: ${SERVICE_NAMES[*]})"
    exit 1
  fi

  if ! is_running "$name"; then
    err "'$name' не запущен. Сначала выполните: $SCRIPT_NAME start"
    exit 1
  fi
  exec screen -r "$name"
}

# ---------------------------------------------------------------------------
# Точка входа
# ---------------------------------------------------------------------------
case "${1:-}" in
  start)   do_start ;;
  stop)    do_stop ;;
  restart) do_restart ;;
  status)  do_status ;;
  attach)  do_attach "${2:-}" ;;
  help|--help|-h|"") usage ;;
  *)
    err "неизвестная команда: $1"
    echo
    usage
    exit 1
    ;;
esac
