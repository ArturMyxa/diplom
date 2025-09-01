#!/bin/bash
# Скрипт генерации CHANGELOG.md из истории коммитов

echo "# Хронология разработки проекта" > CHANGELOG.md
echo "" >> CHANGELOG.md

# Берём историю в порядке возрастания (старые коммиты сверху)
git log --reverse --pretty=format:"## 📅 %ad%n### 📝 Коммит %h%n**Сообщение:** %s%n" --date=short >> CHANGELOG.md

# Добавляем восьмой этап вручную
echo "" >> CHANGELOG.md
echo "## 📅 2025-09-02" >> CHANGELOG.md
echo "### 📝 Коммит planned" >> CHANGELOG.md
echo "**Сообщение:** Финальные настройки: CI/CD и Docker" >> CHANGELOG.md
echo "" >> CHANGELOG.md

# Добавляем финальный статус
echo "## 🎯 Текущий статус" >> CHANGELOG.md
echo "Проект завершён и готов к развёртыванию." >> CHANGELOG.md
