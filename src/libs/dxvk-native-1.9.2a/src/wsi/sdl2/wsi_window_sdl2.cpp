#include "../wsi_window.h"

#include "wsi_helpers_sdl2.h"

#include <windows.h>
#include <wsi/native_wsi.h>

#include "../../util/util_string.h"
#include "../../util/log/log.h"

namespace dxvk::wsi {

  void getWindowSize(
        HWND      hWindow,
        uint32_t* pWidth,
        uint32_t* pHeight) {
    SDL_Window* window = fromHwnd(hWindow);

    int32_t w, h;
    SDL_GetWindowSize(window, &w, &h);

    if (pWidth)
      *pWidth = uint32_t(w);

    if (pHeight)
      *pHeight = uint32_t(h);
  }


  void resizeWindow(
          HWND             hWindow,
          DxvkWindowState* pState,
          uint32_t         Width,
          uint32_t         Height) {
    SDL_Window* window = fromHwnd(hWindow);

    SDL_SetWindowSize(window, int32_t(Width), int32_t(Height));
  }


  bool setWindowMode(
          HMONITOR         hMonitor,
          HWND             hWindow,
    const WsiMode*         pMode,
          bool             EnteringFullscreen) {
    const int32_t displayId    = fromHmonitor(hMonitor);
    SDL_Window* window         = fromHwnd(hWindow);

    if (!isDisplayValid(displayId))
      return false;

    SDL_DisplayMode wantedMode = { };
    wantedMode.w            = pMode->width;
    wantedMode.h            = pMode->height;
    wantedMode.refresh_rate = pMode->refreshRate.numerator != 0
      ? pMode->refreshRate.numerator / pMode->refreshRate.denominator
      : 0;
    // TODO: Implement lookup format for bitsPerPixel here.

    SDL_DisplayMode mode = { };
    if (SDL_GetClosestDisplayMode(displayId, &wantedMode, &mode) == nullptr) {
      Logger::err(str::format("SDL2 WSI: setWindowMode: SDL_GetClosestDisplayMode: ", SDL_GetError()));
      return false;
    }

    if (SDL_SetWindowDisplayMode(window, &mode) != 0) {
      Logger::err(str::format("SDL2 WSI: setWindowMode: SDL_SetWindowDisplayMode: ", SDL_GetError()));
      return false;
    }

    return true;
  }



  bool enterFullscreenMode(
          HMONITOR         hMonitor,
          HWND             hWindow,
          DxvkWindowState* pState,
          bool             ModeSwitch) {
    const int32_t displayId    = fromHmonitor(hMonitor);
    SDL_Window* window         = fromHwnd(hWindow);

    if (!isDisplayValid(displayId))
      return false;

    uint32_t flags = ModeSwitch
        ? SDL_WINDOW_FULLSCREEN
        : SDL_WINDOW_FULLSCREEN_DESKTOP;
    
    // TODO: Set this on the correct monitor.
    // Docs aren't clear on this...
    if (SDL_SetWindowFullscreen(window, flags) != 0) {
      Logger::err(str::format("SDL2 WSI: enterFullscreenMode: SDL_SetWindowFullscreen: ", SDL_GetError()));
      return false;
    }

    return true;
  }


  bool leaveFullscreenMode(
          HWND             hWindow,
          DxvkWindowState* pState) {
    SDL_Window* window = fromHwnd(hWindow);

    if (SDL_SetWindowFullscreen(window, 0) != 0) {
      Logger::err(str::format("SDL2 WSI: leaveFullscreenMode: SDL_SetWindowFullscreen: ", SDL_GetError()));
      return false;
    }

    return true;
  }


  bool restoreDisplayMode(HMONITOR hMonitor) {
    const int32_t displayId = fromHmonitor(hMonitor);
    return isDisplayValid(displayId);
  }


  HMONITOR getWindowMonitor(HWND hWindow) {
    SDL_Window* window      = fromHwnd(hWindow);
    const int32_t displayId = SDL_GetWindowDisplayIndex(window);

    return toHmonitor(displayId);
  }


  bool isWindow(HWND hWindow) {
    SDL_Window* window = fromHwnd(hWindow);
    return window != nullptr;
  }

}