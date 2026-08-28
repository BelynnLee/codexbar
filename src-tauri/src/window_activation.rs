use tauri::{Manager, Runtime, WebviewWindow};

pub(crate) trait WindowActivation {
    type Error;

    fn unminimize(&self) -> Result<(), Self::Error>;
    fn show(&self) -> Result<(), Self::Error>;
    fn focus(&self) -> Result<(), Self::Error>;
}

impl<R: Runtime> WindowActivation for WebviewWindow<R> {
    type Error = tauri::Error;

    fn unminimize(&self) -> Result<(), Self::Error> {
        WebviewWindow::unminimize(self)
    }

    fn show(&self) -> Result<(), Self::Error> {
        WebviewWindow::show(self)
    }

    fn focus(&self) -> Result<(), Self::Error> {
        self.set_focus()
    }
}

pub(crate) fn activate<W: WindowActivation>(window: &W) -> Result<(), W::Error> {
    window.unminimize()?;
    window.show()?;
    window.focus()
}

pub(crate) fn show_main_window<R: Runtime>(app: &tauri::AppHandle<R>) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = activate(&window);
    }
}

#[cfg(test)]
mod tests {
    use super::{WindowActivation, activate};
    use std::{cell::RefCell, convert::Infallible};

    struct FakeWindow(RefCell<Vec<&'static str>>);

    impl WindowActivation for FakeWindow {
        type Error = Infallible;

        fn unminimize(&self) -> Result<(), Self::Error> {
            self.0.borrow_mut().push("unminimize");
            Ok(())
        }

        fn show(&self) -> Result<(), Self::Error> {
            self.0.borrow_mut().push("show");
            Ok(())
        }

        fn focus(&self) -> Result<(), Self::Error> {
            self.0.borrow_mut().push("focus");
            Ok(())
        }
    }

    #[test]
    fn activation_restores_shows_and_focuses_the_existing_window() {
        let window = FakeWindow(RefCell::new(Vec::new()));

        activate(&window).unwrap();

        assert_eq!(*window.0.borrow(), ["unminimize", "show", "focus"]);
    }
}
