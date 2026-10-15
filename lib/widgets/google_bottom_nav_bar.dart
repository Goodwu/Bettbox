import 'dart:math' as math;
import 'package:bett_box/common/common.dart';
import 'package:bett_box/enum/enum.dart';
import 'package:bett_box/models/common.dart';
import 'package:bett_box/providers/providers.dart';
import 'package:flutter/foundation.dart';
import 'package:material_ui/material_ui.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

class GoogleBottomNavBar extends ConsumerStatefulWidget {
  final List<NavigationItem> navigationItems;
  final int selectedIndex;
  final ValueChanged<int> onTabChange;

  const GoogleBottomNavBar({
    super.key,
    required this.navigationItems,
    required this.selectedIndex,
    required this.onTabChange,
  });

  @override
  ConsumerState<GoogleBottomNavBar> createState() => _GoogleBottomNavBarState();
}

class _GoogleBottomNavBarState extends ConsumerState<GoogleBottomNavBar>
    with TickerProviderStateMixin {
  late final AnimationController _posController = AnimationController.unbounded(
    vsync: this,
    value: widget.selectedIndex.toDouble(),
  );

  late final AnimationController _liftController = AnimationController(
    vsync: this,
    duration: const Duration(milliseconds: 140),
  );

  int? _activePointerId;
  bool _isDragging = false;
  bool _dragCancel = false;
  Offset? _downPosition;
  double _anchorSlot = 0.0;
  double _barWidth = 0;
  int _lastSnappedIndex = 0;
  int _lastHapticTime = 0;
  int _lastMoveTime = 0;
  double _lastMoveDx = 0.0;
  double _velocityX = 0.0;
  late final ValueNotifier<int> _highlightedIndex = ValueNotifier(
    widget.selectedIndex,
  );
  late final ValueNotifier<int?> _pressedIndex = ValueNotifier(null);
  final ValueNotifier<double> _dragOffset = ValueNotifier(0.0);

  static const double _horizontalInset = 17.0;

  double? _posTarget;
  bool _motion = true;

  void _glideTo(int index, int milliseconds) {
    _posTarget = index.toDouble();
    if (milliseconds <= 0) {
      _posController.value = index.toDouble();
      return;
    }
    _posController.animateTo(
      index.toDouble(),
      duration: Duration(milliseconds: milliseconds),
      curve: Curves.easeOutCubic,
    );
  }

  void _liftTo(double value, int milliseconds) {
    _liftController.animateTo(
      value,
      duration: Duration(milliseconds: milliseconds),
      curve: Curves.easeOutCubic,
    );
  }

  @override
  void initState() {
    super.initState();
    _lastSnappedIndex = widget.selectedIndex;
  }

  @override
  void didUpdateWidget(covariant GoogleBottomNavBar oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (widget.selectedIndex != oldWidget.selectedIndex &&
        _activePointerId == null) {
      _highlightedIndex.value = widget.selectedIndex;
      _lastSnappedIndex = widget.selectedIndex;
      if (!_posController.isAnimating) {
        _glideTo(widget.selectedIndex, _motion ? 160 : 0);
      }
    }
  }

  @override
  void dispose() {
    _highlightedIndex.dispose();
    _pressedIndex.dispose();
    _dragOffset.dispose();
    _posController.dispose();
    _liftController.dispose();
    super.dispose();
  }

  void _triggerHapticFeedback(bool enableFeedback) {
    if (system.isAndroid && enableFeedback) {
      final now = DateTime.now().millisecondsSinceEpoch;
      if (now - _lastHapticTime > 35) {
        _lastHapticTime = now;
        HapticFeedback.selectionClick();
      }
    }
  }

  double _clampWithResistance(double slot, int count) {
    const maxOvershoot = 0.22;
    final maxIndex = math.max(0, count - 1).toDouble();
    if (slot < 0.0) {
      return -maxOvershoot * (1.0 - math.exp(slot / maxOvershoot));
    }
    if (slot > maxIndex) {
      return maxIndex +
          maxOvershoot * (1.0 - math.exp((maxIndex - slot) / maxOvershoot));
    }
    return slot;
  }

  double get _slotWidth {
    final count = widget.navigationItems.length;
    if (count == 0) return 0.0;
    return math.max(0.0, _barWidth - 2.0) / count;
  }

  void _commitDragOffset() {
    if (_dragOffset.value == 0.0) return;
    _posController.value = _clampWithResistance(
      _posController.value + _dragOffset.value,
      widget.navigationItems.length,
    );
    _dragOffset.value = 0.0;
  }

  int _indexFromLocalDx(double dx) {
    const borderWidth = 1.0;
    final innerWidth = math.max(0.0, _barWidth - (2 * borderWidth));
    final count = widget.navigationItems.length;
    if (innerWidth <= 0 || count == 0) return widget.selectedIndex;
    final slotWidth = innerWidth / count;
    final localDx = (dx - borderWidth).clamp(0.0, innerWidth - 0.001);
    return (localDx / slotWidth).floor().clamp(0, count - 1);
  }

  @override
  Widget build(BuildContext context) {
    final enableFeedback = ref.watch(
      appSettingProvider.select((state) => state.enableNavBarHapticFeedback),
    );
    _motion = enableFeedback;
    final pureBlack = ref.watch(
      themeSettingProvider.select((s) => s.pureBlack),
    );
    final colorScheme = context.colorScheme;
    final isLight = colorScheme.brightness == Brightness.light;
    final primaryColor = colorScheme.primary;
    final onSurfaceVariantColor = colorScheme.onSurfaceVariant;

    // Body color matching CommonCard (widget) formula for visual harmony
    final widgetBodyColor = isLight
        ? Color.lerp(
            colorScheme.surface,
            colorScheme.surfaceContainerLowest,
            0.5,
          )!
        : (pureBlack ? Colors.black : colorScheme.surfaceContainerHigh);

    final navColor = widgetBodyColor.withValues(alpha: 0.98);
    final shadowStrength = isLight ? 1.0 : 3.0;

    const itemTextStyle = TextStyle(
      fontSize: 10.5,
      fontWeight: FontWeight.w500,
    );

    final count = widget.navigationItems.length;

    return SafeArea(
      top: false,
      left: false,
      right: false,
      minimum: const EdgeInsets.only(bottom: 12),
      child: Padding(
        padding: const EdgeInsets.only(top: 8),
        child: Listener(
          behavior: HitTestBehavior.opaque,
          onPointerDown: (event) {
            if (_activePointerId != null) return;
            _activePointerId = event.pointer;
            _downPosition = event.localPosition;
            _lastMoveTime = DateTime.now().millisecondsSinceEpoch;
            _lastMoveDx = event.localPosition.dx;
            _velocityX = 0.0;
            _dragCancel = false;
            _isDragging = false;
            _dragOffset.value = 0.0;

            final touchedIndex = _indexFromLocalDx(
              event.localPosition.dx - _horizontalInset,
            );
            _anchorSlot = touchedIndex.toDouble();
            _lastSnappedIndex = touchedIndex;
            _highlightedIndex.value = touchedIndex;
            _pressedIndex.value = touchedIndex;
            if (touchedIndex != widget.selectedIndex) {
              _triggerHapticFeedback(enableFeedback);
            }

            final distance = (_posController.value - touchedIndex.toDouble())
                .abs();
            final glideMs = (120 + (distance * 25)).clamp(130, 180).toInt();
            _glideTo(touchedIndex, _motion ? glideMs : 0);

            _liftTo(1.0, 140);
          },
          onPointerMove: (event) {
            if (_activePointerId != event.pointer || _dragCancel) return;
            final downPos = _downPosition;
            if (downPos == null) return;
            final delta = event.localPosition - downPos;
            if (delta.dy < -50 || delta.dy > 80) {
              _dragCancel = true;
              _isDragging = false;
              _pressedIndex.value = null;
              _highlightedIndex.value = widget.selectedIndex;
              _commitDragOffset();
              _glideTo(widget.selectedIndex, 140);
              _liftTo(0.0, 180);
              return;
            }

            final now = DateTime.now().millisecondsSinceEpoch;
            final dt = now - _lastMoveTime;
            if (dt > 0) {
              final instantV = (event.localPosition.dx - _lastMoveDx) / dt;
              _velocityX = _velocityX * 0.4 + instantV * 0.6;
              _lastMoveTime = now;
              _lastMoveDx = event.localPosition.dx;
            }

            final slotWidth = _slotWidth;
            if (!_isDragging && delta.dx.abs() > 5) {
              _isDragging = true;
            }
            if (!_isDragging || slotWidth <= 0) return;

            _dragOffset.value = delta.dx / slotWidth;
            final index = (_anchorSlot + _dragOffset.value).round().clamp(
              0,
              count - 1,
            );
            _highlightedIndex.value = index;
            _pressedIndex.value = index;
            if (index != _lastSnappedIndex) {
              _lastSnappedIndex = index;
              _triggerHapticFeedback(enableFeedback);
            }
          },
          onPointerUp: (event) {
            if (_activePointerId != event.pointer) return;
            _activePointerId = null;
            _pressedIndex.value = null;
            _liftTo(0.0, 180);
            if (_dragCancel) {
              _dragCancel = false;
              _isDragging = false;
              return;
            }

            final slotWidth = _slotWidth;
            final int targetIndex;
            if (_isDragging && slotWidth > 0) {
              final now = DateTime.now().millisecondsSinceEpoch;
              final isStationary = (now - _lastMoveTime) > 90;
              final effectiveV = isStationary ? 0.0 : _velocityX;
              final velocityBias = (effectiveV * 60.0 / slotWidth).clamp(
                -0.45,
                0.45,
              );
              targetIndex = (_anchorSlot + _dragOffset.value + velocityBias)
                  .round()
                  .clamp(0, count - 1);

              _commitDragOffset();
              _highlightedIndex.value = targetIndex;
              final distance = (_posController.value - targetIndex.toDouble())
                  .abs();
              final snapMs = (100 + (distance * 110)).clamp(120, 180).toInt();
              _glideTo(targetIndex, snapMs);
            } else {
              targetIndex = _indexFromLocalDx(
                event.localPosition.dx - _horizontalInset,
              );
              _highlightedIndex.value = targetIndex;
              final distance = (_posController.value - targetIndex.toDouble())
                  .abs();
              final glideMs = (120 + (distance * 25)).clamp(130, 180).toInt();
              final needsGlide = _posController.isAnimating
                  ? _posTarget != targetIndex.toDouble()
                  : distance > 0.01;
              if (needsGlide) {
                _glideTo(targetIndex, _motion ? glideMs : 0);
              }
            }

            _isDragging = false;
            if (targetIndex != widget.selectedIndex) {
              widget.onTabChange(targetIndex);
            }
          },
          onPointerCancel: (event) {
            if (_activePointerId != event.pointer) return;
            _activePointerId = null;
            _isDragging = false;
            _dragCancel = false;
            _pressedIndex.value = null;
            _highlightedIndex.value = widget.selectedIndex;
            _commitDragOffset();
            _glideTo(widget.selectedIndex, 140);
            _liftTo(0.0, 180);
          },
          child: Padding(
            padding: const EdgeInsets.symmetric(horizontal: _horizontalInset),
            child: LayoutBuilder(
              builder: (context, constraints) {
                _barWidth = constraints.maxWidth;
                const barHeight = 60.0;

                return RepaintBoundary(
                  child: Container(
                    height: barHeight,
                    decoration: BoxDecoration(
                      color: navColor,
                      borderRadius: BorderRadius.circular(30),
                      border: Border.all(
                        color: Colors.transparent,
                        width: 1,
                        strokeAlign: BorderSide.strokeAlignInside,
                      ),
                      boxShadow: [
                        BoxShadow(
                          blurRadius: 24,
                          offset: const Offset(0, 8),
                          color: colorScheme.shadow.withValues(
                            alpha: 0.08 * shadowStrength,
                          ),
                        ),
                        BoxShadow(
                          blurRadius: 3,
                          offset: const Offset(0, 1),
                          color: colorScheme.shadow.withValues(
                            alpha: 0.04 * shadowStrength,
                          ),
                        ),
                      ],
                    ),
                    child: Stack(
                      alignment: Alignment.centerLeft,
                      children: [
                        if (count > 0)
                          Positioned.fill(
                            child: RepaintBoundary(
                              child: CustomPaint(
                                painter: NavBarPillPainter(
                                  position: _posController,
                                  lift: _liftController,
                                  dragOffset: _dragOffset,
                                  count: count,
                                  slot: _clampWithResistance,
                                  color: primaryColor,
                                  baseAlpha: isLight ? 0.12 : 0.20,
                                  activeAlpha: isLight ? 0.18 : 0.26,
                                ),
                              ),
                            ),
                          ),
                        RepaintBoundary(
                          child: ValueListenableBuilder<int>(
                            valueListenable: _highlightedIndex,
                            builder: (context, highlightedIndex, _) {
                              return ValueListenableBuilder<int?>(
                                valueListenable: _pressedIndex,
                                builder: (context, pressedIndex, _) {
                                  return Row(
                                    children: List.generate(count, (index) {
                                      final item =
                                          widget.navigationItems[index];
                                      final isHighlighted =
                                          index == highlightedIndex;
                                      final isPressed = index == pressedIndex;

                                      final itemScale = isPressed
                                          ? 0.94
                                          : (isHighlighted ? 1.04 : 1.0);
                                      final itemColor = isHighlighted
                                          ? primaryColor
                                          : onSurfaceVariantColor;

                                      return Expanded(
                                        child: Center(
                                          child: AnimatedScale(
                                            scale: itemScale,
                                            duration: const Duration(
                                              milliseconds: 120,
                                            ),
                                            curve: Curves.easeOutCubic,
                                            alignment: Alignment.center,
                                            child: TweenAnimationBuilder<Color?>(
                                              tween: ColorTween(
                                                begin: onSurfaceVariantColor,
                                                end: itemColor,
                                              ),
                                              duration: const Duration(
                                                milliseconds: 150,
                                              ),
                                              curve: Curves.easeOut,
                                              builder: (context, color, child) {
                                                return Column(
                                                  mainAxisSize:
                                                      MainAxisSize.min,
                                                  children: [
                                                    IconTheme(
                                                      data: IconThemeData(
                                                        color:
                                                            color ??
                                                            onSurfaceVariantColor,
                                                        size: 22,
                                                      ),
                                                      child: item.icon,
                                                    ),
                                                    const SizedBox(height: 2),
                                                    Text(
                                                      item.label.localizedName,
                                                      style: itemTextStyle
                                                          .copyWith(
                                                            color: color,
                                                          ),
                                                      maxLines: 1,
                                                      overflow:
                                                          TextOverflow.ellipsis,
                                                    ),
                                                  ],
                                                );
                                              },
                                            ),
                                          ),
                                        ),
                                      );
                                    }),
                                  );
                                },
                              );
                            },
                          ),
                        ),
                      ],
                    ),
                  ),
                );
              },
            ),
          ),
        ),
      ),
    );
  }
}

class NavBarPillPainter extends CustomPainter {
  final Animation<double> position;
  final Animation<double> lift;
  final ValueListenable<double> dragOffset;
  final int count;
  final double Function(double slot, int count) slot;
  final Color color;
  final double baseAlpha;
  final double activeAlpha;

  NavBarPillPainter({
    required this.position,
    required this.lift,
    required this.dragOffset,
    required this.count,
    required this.slot,
    required this.color,
    required this.baseAlpha,
    required this.activeAlpha,
  }) : super(repaint: Listenable.merge([position, lift, dragOffset]));

  static const double _restingGap = 4.0;

  Rect pillRect(Size size) {
    final slotWidth = size.width / count;
    final gap = _restingGap * (1 - lift.value);
    final width = math.max(0.0, slotWidth - 2 * gap);
    final center =
        (slot(position.value + dragOffset.value, count) + 0.5) * slotWidth;
    return Rect.fromLTWH(center - width / 2, gap, width, size.height - 2 * gap);
  }

  @override
  void paint(Canvas canvas, Size size) {
    final t = lift.value;
    final restingRadius = (size.height - 2 * _restingGap) / 2;
    final radius = restingRadius + (size.height / 2 - restingRadius) * t;
    final alpha = baseAlpha + (activeAlpha - baseAlpha) * t;
    canvas.clipRRect(
      RRect.fromRectAndRadius(
        Offset.zero & size,
        Radius.circular(size.height / 2),
      ),
    );
    canvas.drawRRect(
      RRect.fromRectAndRadius(pillRect(size), Radius.circular(radius)),
      Paint()..color = color.withValues(alpha: alpha),
    );
  }

  @override
  bool shouldRepaint(NavBarPillPainter oldDelegate) {
    return oldDelegate.position != position ||
        oldDelegate.lift != lift ||
        oldDelegate.dragOffset != dragOffset ||
        oldDelegate.count != count ||
        oldDelegate.color != color ||
        oldDelegate.baseAlpha != baseAlpha ||
        oldDelegate.activeAlpha != activeAlpha;
  }
}
