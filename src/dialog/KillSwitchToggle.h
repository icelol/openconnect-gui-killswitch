// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once
#include <QCheckBox>
#include <QPainter>
#include <QStyleOptionButton>

// One accessible two-position switch; keyboard/checked semantics stay native.
class KillSwitchToggle : public QCheckBox {
    Q_OBJECT
public:
    explicit KillSwitchToggle(QWidget* parent = nullptr) : QCheckBox(parent) {
        setCursor(Qt::PointingHandCursor);
        setMinimumHeight(34);
    }
    QSize sizeHint() const override {
        return QSize(58 + fontMetrics().horizontalAdvance(text()), qMax(34, fontMetrics().height() + 8));
    }
protected:
    bool hitButton(const QPoint& position) const override { return rect().contains(position); }
    void paintEvent(QPaintEvent*) override {
        QPainter painter(this);
        painter.setRenderHint(QPainter::Antialiasing);
        const QRectF track(2, (height() - 24) / 2.0, 44, 24);
        painter.setPen(Qt::NoPen);
        painter.setBrush(isEnabled() ? (isChecked() ? QColor("#087f72") : QColor("#72777f")) : QColor("#a5a5a5"));
        painter.drawRoundedRect(track, 12, 12);
        painter.setBrush(Qt::white);
        painter.drawEllipse(QRectF(track.left() + (isChecked() ? 23 : 3), track.top() + 3, 18, 18));
        painter.setPen(palette().color(isEnabled() ? QPalette::Active : QPalette::Disabled, QPalette::WindowText));
        painter.drawText(QRect(56, 0, width() - 56, height()), Qt::AlignVCenter | Qt::AlignLeft, text());
        if (hasFocus()) {
            painter.setPen(QPen(palette().color(QPalette::Highlight), 1, Qt::DotLine));
            painter.setBrush(Qt::NoBrush);
            painter.drawRoundedRect(rect().adjusted(0, 0, -1, -1), 4, 4);
        }
    }
};
