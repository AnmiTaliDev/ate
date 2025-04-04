// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2025 AnmiTaliDev

namespace ATE.Utils;

/// <summary>
/// Console progress bar implementation
/// </summary>
internal sealed class ProgressBar : IProgress<double>, IDisposable
{
    private const int BarWidth = 50;
    private const string Animation = @"|/-\";
    private readonly Timer _timer;
    private bool _disposed;
    private int _animationIndex;
    private double _currentProgress;
    private string _currentText = string.Empty;

    public ProgressBar()
    {
        _timer = new Timer(TimerHandler);
        
        if (!Console.IsOutputRedirected)
        {
            _timer.Change(TimeSpan.Zero, TimeSpan.FromMilliseconds(100));
        }
    }

    public void Report(double progress)
    {
        _currentProgress = Math.Max(0, Math.Min(1, progress));
        
        if (!Console.IsOutputRedirected)
        {
            lock (this)
            {
                UpdateProgress();
            }
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        
        lock (this)
        {
            _timer.Dispose();
            
            if (!Console.IsOutputRedirected)
            {
                UpdateProgress();
                Console.WriteLine();
            }
            
            _disposed = true;
        }
    }

    private void UpdateProgress()
    {
        if (_disposed) return;

        var progressBlocks = (int)(_currentProgress * BarWidth);
        var percent = (int)(_currentProgress * 100);
        
        var text = string.Create(BarWidth + 10, progressBlocks, (span, blocks) =>
        {
            span[0] = '[';
            
            for (var i = 0; i < BarWidth; i++)
            {
                span[i + 1] = i < blocks ? '=' : ' ';
            }
            
            span[BarWidth + 1] = ']';
            span[BarWidth + 2] = ' ';
            
            var percentStr = $"{percent,3}%";
            percentStr.CopyTo(span[(BarWidth + 3)..]);
        });

        var animation = Animation[_animationIndex++ % Animation.Length];
        text = $"{animation} {text}";

        if (text == _currentText) return;
        
        _currentText = text;
        Console.Write($"\r{_currentText}");
    }

    private void TimerHandler(object? state)
    {
        lock (this)
        {
            if (!_disposed)
            {
                UpdateProgress();
            }
        }
    }
}