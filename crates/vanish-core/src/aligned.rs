//! Выровненный буфер: нужен для bypass-IO (O_DIRECT / FILE_FLAG_NO_BUFFERING).
//! Ноль-страница при drop (zeroize): содержимое файлов не царапает память.

use zeroize::Zeroize;

const ALIGN: usize = 4096;

pub struct AlignedBuf {
    ptr: std::ptr::NonNull<u8>,
    len: usize,
    cap: usize,
    _pin: std::marker::PhantomData<u8>,
}

// Владелец — один; буфер переносим между потоками только через &mut под sync-точками ядра.
unsafe impl Send for AlignedBuf {}

impl AlignedBuf {
    pub fn zeroed(len: usize) -> Self {
        let cap = len.next_multiple_of(4096);
        let layout = std::alloc::Layout::from_size_align(cap.max(ALIGN), ALIGN)
            .expect("aligned layout");
        unsafe {
            let ptr = std::alloc::alloc_zeroed(layout);
            let ptr = std::ptr::NonNull::new(ptr).expect("alloc_zeroed");
            AlignedBuf {
                ptr,
                len,
                cap,
                _pin: std::marker::PhantomData,
            }
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn as_mut(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len) }
    }

    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.ptr.as_ptr()
    }
}

impl std::ops::Deref for AlignedBuf {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }
}

impl Drop for AlignedBuf {
    fn drop(&mut self) {
        unsafe {
            std::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.cap).zeroize();
            let layout = std::alloc::Layout::from_size_align(self.cap.max(ALIGN), ALIGN)
                .expect("aligned layout at drop");
            std::alloc::dealloc(self.ptr.as_ptr(), layout);
        }
    }
}

/// Размер чанка нашего движка (1 МиБ; O_DIRECT multiples 4096 OK).
pub const CHUNK: usize = 1 << 20;
