//! Segredos em memória que não vão para o swap nem para um core dump, e um
//! processo que outro do mesmo usuário não consegue inspecionar
//! (`docs/seguranca.md`).
//!
//! O único `unsafe` do projeto mora aqui, em volta de uma página de memória
//! que só este módulo conhece.

#[cfg(not(target_os = "linux"))]
compile_error!(
    "memoria: falta a implementação deste sistema (VirtualLock no Windows, mlock no macOS)"
);

use std::io;
use std::ptr::NonNull;

use rustix::mm::{Advice, MapFlags, ProtFlags};
use rustix::process::{DumpableBehavior, Resource, Rlimit};
use zeroize::Zeroize;

/// `N` bytes numa página só deles: travada na RAM (`mlock`), fora de core dump
/// (`MADV_DONTDUMP`) e zerada ao sair de escopo.
pub struct Travado<const N: usize> {
    pagina: NonNull<u8>,
    tamanho: usize,
}

// SAFETY: a página pertence só a este valor; mandá-la a outra thread, ou ler
// por `&` de várias, é o mesmo que com um `Box<[u8; N]>`.
#[allow(unsafe_code)]
unsafe impl<const N: usize> Send for Travado<N> {}
#[allow(unsafe_code)]
unsafe impl<const N: usize> Sync for Travado<N> {}

impl<const N: usize> Travado<N> {
    /// Zeros, prontos para serem preenchidos por [`Travado::expor_mut`] (por
    /// exemplo lendo um arquivo direto para dentro, sem cópia no caminho).
    pub fn zerado() -> io::Result<Self> {
        let tamanho = rustix::param::page_size();
        assert!(N <= tamanho, "um Travado cabe numa página");
        #[allow(unsafe_code)]
        // SAFETY: um mapeamento anônimo novo, que nada mais referencia. O
        // kernel o entrega zerado e alinhado à página, como o mlock e o
        // madvise pedem.
        let pagina = unsafe {
            let ptr = rustix::mm::mmap_anonymous(
                std::ptr::null_mut(),
                tamanho,
                ProtFlags::READ | ProtFlags::WRITE,
                MapFlags::PRIVATE,
            )?;
            let travado = rustix::mm::mlock(ptr, tamanho)
                .and_then(|()| rustix::mm::madvise(ptr, tamanho, Advice::LinuxDontDump));
            if let Err(e) = travado {
                let _ = rustix::mm::munmap(ptr, tamanho);
                return Err(e.into());
            }
            ptr
        };
        Ok(Travado {
            pagina: NonNull::new(pagina.cast()).expect("o mmap não devolve nulo com sucesso"),
            tamanho,
        })
    }

    pub fn aleatorio() -> io::Result<Self> {
        let mut travado = Self::zerado()?;
        getrandom::fill(travado.expor_mut()).map_err(io::Error::from)?;
        Ok(travado)
    }

    pub fn expor(&self) -> &[u8; N] {
        #[allow(unsafe_code)]
        // SAFETY: a página tem pelo menos N bytes, vive enquanto `self` vive e
        // só é escrita por `expor_mut`, que pede `&mut self`.
        unsafe {
            &*self.pagina.as_ptr().cast::<[u8; N]>()
        }
    }

    pub fn expor_mut(&mut self) -> &mut [u8; N] {
        #[allow(unsafe_code)]
        // SAFETY: como em `expor`, e o `&mut self` garante acesso exclusivo.
        unsafe {
            &mut *self.pagina.as_ptr().cast::<[u8; N]>()
        }
    }
}

impl<const N: usize> Drop for Travado<N> {
    fn drop(&mut self) {
        self.expor_mut().zeroize();
        let ptr = self.pagina.as_ptr().cast();
        #[allow(unsafe_code)]
        // SAFETY: o mesmo mapeamento criado em `zerado`, com o mesmo tamanho;
        // depois daqui ninguém mais o usa.
        unsafe {
            let _ = rustix::mm::munlock(ptr, self.tamanho);
            let _ = rustix::mm::munmap(ptr, self.tamanho);
        }
    }
}

/// Outro processo do mesmo usuário não faz `ptrace` neste nem lê a memória dele
/// por `/proc`, e uma queda não deixa core dump. O `execve` volta o primeiro
/// ao normal: todo executável do projeto chama isto no começo do `main`.
pub fn endurecer_processo() -> io::Result<()> {
    rustix::process::set_dumpable_behavior(DumpableBehavior::NotDumpable)?;
    rustix::process::setrlimit(
        Resource::Core,
        Rlimit {
            current: Some(0),
            maximum: Some(0),
        },
    )?;
    Ok(())
}

#[cfg(test)]
mod testes {
    use super::*;

    /// As flags do kernel para o mapeamento que começa em `endereco`
    /// (`VmFlags` do `/proc/self/smaps`).
    fn flags_do_mapeamento(endereco: usize) -> Vec<String> {
        let smaps = std::fs::read_to_string("/proc/self/smaps").unwrap();
        let inicio = format!("{endereco:x}-");
        smaps
            .lines()
            .skip_while(|l| !l.starts_with(&inicio))
            .find_map(|l| l.strip_prefix("VmFlags:"))
            .unwrap()
            .split_whitespace()
            .map(str::to_string)
            .collect()
    }

    #[test]
    fn a_chave_fica_travada_na_ram_e_fora_de_core_dump() {
        let mut chave = Travado::<32>::zerado().unwrap();
        let flags = flags_do_mapeamento(chave.pagina.as_ptr() as usize);
        assert!(flags.contains(&"lo".to_string()), "não travada: {flags:?}");
        assert!(
            flags.contains(&"dd".to_string()),
            "vai para dump: {flags:?}"
        );

        chave.expor_mut()[0] = 7;
        assert_eq!(chave.expor()[0], 7);
        assert_eq!(chave.expor()[1..], [0; 31]);
    }

    #[test]
    fn duas_chaves_aleatorias_diferem() {
        let a = Travado::<32>::aleatorio().unwrap();
        let b = Travado::<32>::aleatorio().unwrap();
        assert_ne!(a.expor(), b.expor());
    }

    #[test]
    fn processo_endurecido_nao_se_deixa_inspecionar_nem_deixa_core() {
        endurecer_processo().unwrap();
        assert_eq!(
            rustix::process::dumpable_behavior().unwrap(),
            DumpableBehavior::NotDumpable
        );
        let core = rustix::process::getrlimit(Resource::Core);
        assert_eq!((core.current, core.maximum), (Some(0), Some(0)));
    }
}
